#include "batch_scheduler.hpp"
#include <iostream>
#include <fstream>
#include <chrono>
#include <cstring>
#include <algorithm>
#include <thread>

namespace samulibre::gpu {

BatchScheduler::BatchScheduler(GPUComputeEngine& engine,
                               SignatureScanner& scanner,
                               MLClassifier& classifier)
    : engine_(engine), scanner_(scanner), classifier_(classifier), monitor_(engine.get_resource_profile()), profile_(engine.get_resource_profile()) {
    init_pipeline_slots();
}

BatchScheduler::~BatchScheduler() {
    release_pipeline_slots();
}

void BatchScheduler::set_profile(ResourceProfile profile) {
    if (profile_ == profile) return;
    profile_ = profile;
    monitor_.set_profile(profile);
    release_pipeline_slots();
    init_pipeline_slots();
}

void BatchScheduler::init_pipeline_slots() {
    uint32_t num_slots = 2; // Default Balanced = Double Buffering (2 slots)

    switch (profile_) {
        case ResourceProfile::SILENT:
            num_slots = 1;
            slot_capacity_bytes_ = 2 * 1024 * 1024; // 2 MB
            break;
        case ResourceProfile::BALANCED:
            num_slots = 2; // Double buffering
            slot_capacity_bytes_ = 8 * 1024 * 1024; // 8 MB
            break;
        case ResourceProfile::PERFORMANCE:
            num_slots = 3; // Triple buffering
            slot_capacity_bytes_ = 16 * 1024 * 1024; // 16 MB
            break;
    }

    slots_.clear();
    slots_.resize(num_slots);

    for (uint32_t i = 0; i < num_slots; ++i) {
        slots_[i].slot_id = i;
        slots_[i].capacity_bytes = slot_capacity_bytes_;

        if (engine_.is_gpu_accelerated()) {
            slots_[i].stream = engine_.create_stream();
            slots_[i].pinned_host_buffer = engine_.allocate_host_buffer(slot_capacity_bytes_);
            slots_[i].device_buffer = engine_.allocate_device_buffer(slot_capacity_bytes_);
            slots_[i].is_allocated = (slots_[i].pinned_host_buffer != nullptr && slots_[i].device_buffer != nullptr);
        } else {
            // CPU fallback allocation
            slots_[i].stream = nullptr;
            slots_[i].pinned_host_buffer = engine_.allocate_host_buffer(slot_capacity_bytes_);
            slots_[i].device_buffer = nullptr;
            slots_[i].is_allocated = (slots_[i].pinned_host_buffer != nullptr);
        }
    }
}

void BatchScheduler::release_pipeline_slots() {
    for (auto& slot : slots_) {
        if (slot.stream) {
            engine_.synchronize_stream(slot.stream);
            engine_.destroy_stream(slot.stream);
            slot.stream = nullptr;
        }
        if (slot.pinned_host_buffer) {
            engine_.free_host_buffer(slot.pinned_host_buffer);
            slot.pinned_host_buffer = nullptr;
        }
        if (slot.device_buffer) {
            engine_.free_device_buffer(slot.device_buffer);
            slot.device_buffer = nullptr;
        }
        slot.is_allocated = false;
    }
    slots_.clear();
}

void BatchScheduler::enqueue_task(const ScanTask& task) {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    task_queue_.push(task);
}

void BatchScheduler::enqueue_file(const std::string& file_path, TaskPriority priority) {
    ScanTask task;
    task.task_id = next_task_id_++;
    task.file_path = file_path;
    task.priority = priority;

    // Read file size safely with validation (VULN-02 fix)
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (file.is_open()) {
        std::streamsize sz = file.tellg();
        if (sz > 0 && static_cast<size_t>(sz) <= MAX_SCAN_FILE_SIZE) {
            task.file_size = static_cast<size_t>(sz);
        } else if (sz > 0) {
            task.file_size = MAX_SCAN_FILE_SIZE; // Bound to max limit
        } else {
            task.file_size = 0;
        }
    }

    enqueue_task(task);
}

void BatchScheduler::enqueue_buffer(const uint8_t* data, size_t size,
                                    const std::string& virtual_path,
                                    TaskPriority priority) {
    ScanTask task;
    task.task_id = next_task_id_++;
    task.file_path = virtual_path;
    task.file_size = size;
    task.priority = priority;
    if (data && size > 0) {
        task.inline_data.assign(data, data + size);
    }
    enqueue_task(task);
}

size_t BatchScheduler::pending_tasks_count() {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return task_queue_.size();
}

void BatchScheduler::clear_queue() {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    std::queue<ScanTask> empty;
    std::swap(task_queue_, empty);
}

TaskScanReport BatchScheduler::execute_task_cpu_fallback(const ScanTask& task) {
    TaskScanReport report;
    report.task_id = task.task_id;
    report.file_path = task.file_path;
    report.stream_id = 0;
    report.backend_used = "CPU_AVX2_Fallback";

    const uint8_t* scan_data = nullptr;
    size_t scan_size = 0;
    std::vector<uint8_t> file_disk_buffer;

    if (!task.inline_data.empty()) {
        scan_data = task.inline_data.data();
        scan_size = task.inline_data.size();
    } else if (!task.file_path.empty()) {
        std::ifstream file(task.file_path, std::ios::binary | std::ios::ate);
        if (file.is_open()) {
            std::streamsize fsize = file.tellg();
            file.seekg(0, std::ios::beg);
            if (fsize > 0) {
                size_t to_read = std::min(static_cast<size_t>(fsize), MAX_SCAN_FILE_SIZE);
                try {
                    file_disk_buffer.resize(to_read);
                    if (file.read(reinterpret_cast<char*>(file_disk_buffer.data()), to_read)) {
                        scan_data = file_disk_buffer.data();
                        scan_size = to_read;
                    }
                } catch (const std::bad_alloc&) {
                    report.final_verdict = "CLEAN";
                    return report;
                }
            }
        }
    }

    report.file_size = scan_size;
    if (!scan_data || scan_size == 0) {
        report.final_verdict = "CLEAN";
        return report;
    }

    // Direct Host CPU execution for micro-files
    auto start_total = std::chrono::high_resolution_clock::now();

    auto scan_res = scanner_.scan_buffer(scan_data, scan_size, static_cast<int>(task.task_id));
    report.shannon_entropy = scan_res.entropy_shannon;
    report.is_suspicious_packed = scan_res.is_suspicious_packed;
    report.pattern_matches = scan_res.matches;

    auto ml_res = classifier_.classify_buffer(scan_data, scan_size, task.file_path, task.task_id);
    report.ml_risk_probability = ml_res.risk_probability;
    report.ml_classification = ml_res.classification_label;
    report.ml_contributing_features = ml_res.contributing_features;

    auto end_total = std::chrono::high_resolution_clock::now();
    report.gpu_compute_time_ms = 0.0;
    report.pcie_dma_time_ms = 0.0;
    report.total_duration_ms = std::chrono::duration<double, std::milli>(end_total - start_total).count();

    // Zero-Trust Correlation Engine
    if (!report.pattern_matches.empty()) {
        report.final_verdict = "MALICIOUS";
        report.quarantine_recommended = true;
    } else if (report.ml_classification == "MALICIOUS" && (report.is_suspicious_packed || report.shannon_entropy >= 7.20)) {
        report.final_verdict = "MALICIOUS";
        report.quarantine_recommended = true;
    } else if (report.ml_classification == "MALICIOUS") {
        report.final_verdict = "SUSPICIOUS";
        report.quarantine_recommended = false;
    } else if (report.ml_classification == "SUSPICIOUS" || report.is_suspicious_packed) {
        report.final_verdict = "SUSPICIOUS";
        report.quarantine_recommended = false;
    } else {
        report.final_verdict = "CLEAN";
        report.quarantine_recommended = false;
    }

    return report;
}

TaskScanReport BatchScheduler::execute_task_on_slot(const ScanTask& task, PipelineSlot& slot) {
    TaskScanReport report;
    report.task_id = task.task_id;
    report.file_path = task.file_path;
    report.stream_id = slot.slot_id;
    report.backend_used = engine_.get_active_backend_name();

    const uint8_t* scan_data = nullptr;
    size_t scan_size = 0;
    std::vector<uint8_t> file_disk_buffer;

    // 1. Stage Data: Either from inline memory or read from disk
    if (!task.inline_data.empty()) {
        scan_data = task.inline_data.data();
        scan_size = task.inline_data.size();
    } else if (!task.file_path.empty()) {
        std::ifstream file(task.file_path, std::ios::binary | std::ios::ate);
        if (file.is_open()) {
            std::streamsize fsize = file.tellg();
            file.seekg(0, std::ios::beg);
            if (fsize > 0) {
                size_t to_read = std::min(static_cast<size_t>(fsize), MAX_SCAN_FILE_SIZE);
                try {
                    file_disk_buffer.resize(to_read);
                    if (file.read(reinterpret_cast<char*>(file_disk_buffer.data()), to_read)) {
                        scan_data = file_disk_buffer.data();
                        scan_size = to_read;
                    }
                } catch (const std::bad_alloc&) {
                    report.final_verdict = "CLEAN";
                    return report; // Gracefully handle memory exhaustion
                }
            }
        }
    }

    report.file_size = scan_size;
    if (!scan_data || scan_size == 0) {
        report.final_verdict = "CLEAN";
        return report;
    }

    // Intelligent Scheduling Policy (INFO-01 & PERF-01):
    // Micro-files (< 32 KB) have higher throughput on Host CPU due to zero PCIe bus latency
    if (!engine_.is_gpu_accelerated() || scan_size < 32768) {
        return execute_task_cpu_fallback(task);
    }

    auto start_total = std::chrono::high_resolution_clock::now();

    // 2. Transfer Data to Pinned Staging Buffer
    size_t transfer_chunk = std::min(scan_size, slot.capacity_bytes);
    if (slot.pinned_host_buffer && transfer_chunk > 0) {
        std::memcpy(slot.pinned_host_buffer, scan_data, transfer_chunk);
    }

    // 3. PCIe DMA Transfer Timing
    auto dma_start = std::chrono::high_resolution_clock::now();
    if (engine_.is_gpu_accelerated() && slot.device_buffer && slot.stream) {
        engine_.transfer_to_device(slot.device_buffer, slot.pinned_host_buffer, transfer_chunk, slot.stream);
    }
    auto dma_end = std::chrono::high_resolution_clock::now();
    report.pcie_dma_time_ms = std::chrono::duration<double, std::milli>(dma_end - dma_start).count();

    // 4. Parallel GPU Kernel Compute Timing (Signature Scanner + Entropy)
    auto compute_start = std::chrono::high_resolution_clock::now();

    auto scan_res = scanner_.scan_buffer(scan_data, scan_size, static_cast<int>(task.task_id));
    report.shannon_entropy = scan_res.entropy_shannon;
    report.is_suspicious_packed = scan_res.is_suspicious_packed;
    report.pattern_matches = scan_res.matches;

    // 5. Machine Learning Ingestion (Phase 5)
    auto ml_res = classifier_.classify_buffer(scan_data, scan_size, task.file_path, task.task_id);
    report.ml_risk_probability = ml_res.risk_probability;
    report.ml_classification = ml_res.classification_label;
    report.ml_contributing_features = ml_res.contributing_features;

    auto compute_end = std::chrono::high_resolution_clock::now();
    report.gpu_compute_time_ms = std::chrono::duration<double, std::milli>(compute_end - compute_start).count();

    auto end_total = std::chrono::high_resolution_clock::now();
    report.total_duration_ms = std::chrono::duration<double, std::milli>(end_total - start_total).count();

    // 6. Asymmetric Zero-Trust Correlation Engine
    // Rule A: Hard malware pattern match -> Immediate MALICIOUS verdict
    if (!report.pattern_matches.empty()) {
        report.final_verdict = "MALICIOUS";
        report.quarantine_recommended = true;
    }
    // Rule B: ML indicates MALICIOUS AND verified with high entropy/packing
    else if (report.ml_classification == "MALICIOUS" && (report.is_suspicious_packed || report.shannon_entropy >= 7.20)) {
        report.final_verdict = "MALICIOUS";
        report.quarantine_recommended = true;
    }
    // Rule C: ML indicates MALICIOUS without high entropy (e.g. system tools with execve/chmod)
    else if (report.ml_classification == "MALICIOUS") {
        report.final_verdict = "SUSPICIOUS";
        report.quarantine_recommended = false; // Protected from destructive quarantine
    }
    // Rule D: ML indicates SUSPICIOUS or file is packed
    else if (report.ml_classification == "SUSPICIOUS" || report.is_suspicious_packed) {
        report.final_verdict = "SUSPICIOUS";
        report.quarantine_recommended = false;
    }
    // Rule E: Clean binary
    else {
        report.final_verdict = "CLEAN";
        report.quarantine_recommended = false;
    }

    return report;
}

TaskScanReport BatchScheduler::process_single_task(const ScanTask& task) {
    if (slots_.empty()) init_pipeline_slots();
    return execute_task_on_slot(task, slots_[0]);
}

BatchMetrics BatchScheduler::process_all(TaskCallback callback) {
    BatchMetrics metrics;
    if (slots_.empty()) init_pipeline_slots();

    metrics.active_streams = static_cast<uint32_t>(slots_.size());
    metrics.pinned_buffer_size_bytes = slot_capacity_bytes_;

    auto wall_start = std::chrono::high_resolution_clock::now();
    size_t slot_idx = 0;

    while (true) {
        // 1. Cooperative cancellation & Emergency throttle check
        if (monitor_.is_cancellation_requested() || monitor_.is_emergency_pause_active()) {
            break;
        }

        monitor_.evaluate_and_throttle();

        ScanTask task;
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (task_queue_.empty()) break;
            task = task_queue_.front();
            task_queue_.pop();
        }

        auto& slot = slots_[slot_idx % slots_.size()];
        slot_idx++;

        TaskScanReport report = execute_task_on_slot(task, slot);

        metrics.total_tasks++;
        metrics.total_bytes_scanned += report.file_size;
        if (report.final_verdict == "MALICIOUS") {
            metrics.total_threats_found++;
        }

        metrics.cumulative_dma_transfer_ms += report.pcie_dma_time_ms;
        metrics.cumulative_kernel_compute_ms += report.gpu_compute_time_ms;

        if (callback) {
            callback(report);
        }

        // Silent mode throttle
        if (profile_ == ResourceProfile::SILENT) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }

    // Synchronize all pipeline streams
    for (auto& slot : slots_) {
        if (slot.stream) {
            engine_.synchronize_stream(slot.stream);
        }
    }

    auto wall_end = std::chrono::high_resolution_clock::now();
    metrics.total_wall_time_ms = std::chrono::duration<double, std::milli>(wall_end - wall_start).count();

    if (metrics.total_wall_time_ms > 0.0) {
        double mb = static_cast<double>(metrics.total_bytes_scanned) / (1024.0 * 1024.0);
        metrics.throughput_mb_s = mb / (metrics.total_wall_time_ms / 1000.0);

        double serial_sum = metrics.cumulative_dma_transfer_ms + metrics.cumulative_kernel_compute_ms;
        if (serial_sum > 0.0) {
            metrics.overlap_efficiency_ratio = serial_sum / metrics.total_wall_time_ms;
        }
    }

    return metrics;
}

} // namespace samulibre::gpu
