#include "samulibre_gpu_ffi.h"
#include "compute_engine.hpp"
#include "signature_scanner.hpp"
#include "ml_classifier.hpp"
#include "batch_scheduler.hpp"
#include "resource_monitor.hpp"
#include <cstring>
#include <memory>
#include <algorithm>

namespace samulibre::gpu {

struct GPUContextInternal {
    std::unique_ptr<GPUComputeEngine> engine;
    std::unique_ptr<SignatureScanner> scanner;
    std::unique_ptr<MLClassifier> classifier;
    std::unique_ptr<BatchScheduler> scheduler;

    explicit GPUContextInternal(ResourceProfile prof) {
        engine = std::make_unique<GPUComputeEngine>(prof);
        engine->initialize();
        scanner = std::make_unique<SignatureScanner>(*engine);
        classifier = std::make_unique<MLClassifier>(*engine, scanner.get());
        scheduler = std::make_unique<BatchScheduler>(*engine, *scanner, *classifier);
    }
};

} // namespace samulibre::gpu

using namespace samulibre::gpu;

extern "C" {

SamulibreGPUContext samulibre_gpu_create(int32_t profile_mode) {
    try {
        ResourceProfile prof = ResourceProfile::BALANCED;
        if (profile_mode == SAMULIBRE_GPU_PROFILE_SILENT) prof = ResourceProfile::SILENT;
        else if (profile_mode == SAMULIBRE_GPU_PROFILE_PERFORMANCE) prof = ResourceProfile::PERFORMANCE;

        auto* ctx = new GPUContextInternal(prof);
        return static_cast<SamulibreGPUContext>(ctx);
    } catch (...) {
        return nullptr;
    }
}

void samulibre_gpu_destroy(SamulibreGPUContext ctx) {
    if (!ctx) return;
    try {
        auto* internal = static_cast<GPUContextInternal*>(ctx);
        delete internal;
    } catch (...) {}
}

int32_t samulibre_gpu_is_accelerated(SamulibreGPUContext ctx) {
    if (!ctx) return 0;
    try {
        auto* internal = static_cast<GPUContextInternal*>(ctx);
        return (internal->engine && internal->engine->is_gpu_accelerated()) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

const char* samulibre_gpu_get_backend_name(SamulibreGPUContext ctx) {
    if (!ctx) return "UNKNOWN";
    try {
        auto* internal = static_cast<GPUContextInternal*>(ctx);
        static thread_local std::string backend_name;
        backend_name = internal->engine ? internal->engine->get_active_backend_name() : "NONE";
        return backend_name.c_str();
    } catch (...) {
        return "ERROR";
    }
}

static void fill_c_result(const TaskScanReport& rep, SamulibreCScanResult* out_result) {
    if (!out_result) return;
    std::memset(out_result, 0, sizeof(SamulibreCScanResult));

    if (rep.final_verdict == "MALICIOUS") {
        out_result->status = SAMULIBRE_GPU_STATUS_INFECTED;
    } else if (rep.final_verdict == "SUSPICIOUS") {
        out_result->status = SAMULIBRE_GPU_STATUS_SUSPICIOUS;
    } else {
        out_result->status = SAMULIBRE_GPU_STATUS_CLEAN;
    }

    // Threat name resolution
    if (!rep.pattern_matches.empty()) {
        std::strncpy(out_result->detection_name, rep.pattern_matches[0].rule_name.c_str(), sizeof(out_result->detection_name) - 1);
    } else if (!rep.ml_classification.empty() && rep.final_verdict != "CLEAN") {
        std::string desc = "ML.Heuristic." + rep.ml_classification;
        std::strncpy(out_result->detection_name, desc.c_str(), sizeof(out_result->detection_name) - 1);
    } else {
        std::strncpy(out_result->detection_name, "None", sizeof(out_result->detection_name) - 1);
    }

    std::strncpy(out_result->engine_name, rep.backend_used.c_str(), sizeof(out_result->engine_name) - 1);
    out_result->entropy = rep.shannon_entropy;
    out_result->is_packed = rep.is_suspicious_packed ? 1 : 0;
    out_result->ml_risk_probability = rep.ml_risk_probability;
    std::strncpy(out_result->ml_verdict, rep.ml_classification.c_str(), sizeof(out_result->ml_verdict) - 1);
    out_result->scan_time_ms = static_cast<uint64_t>(rep.total_duration_ms);
    out_result->quarantine_recommended = rep.quarantine_recommended ? 1 : 0;
}

int32_t samulibre_gpu_scan_file(SamulibreGPUContext ctx, const char* file_path, SamulibreCScanResult* out_result) {
    if (!ctx || !file_path || !out_result) return 0;
    try {
        auto* internal = static_cast<GPUContextInternal*>(ctx);
        if (!internal->scheduler) return 0;
        ScanTask task;
        task.task_id = 1;
        task.file_path = file_path;
        TaskScanReport rep = internal->scheduler->process_single_task(task);
        fill_c_result(rep, out_result);
        return 1;
    } catch (...) {
        return 0;
    }
}

int32_t samulibre_gpu_scan_buffer(SamulibreGPUContext ctx, const uint8_t* data, size_t size,
                                  const char* virtual_name, SamulibreCScanResult* out_result) {
    if (!ctx || !data || !out_result) return 0;
    try {
        auto* internal = static_cast<GPUContextInternal*>(ctx);
        if (!internal->scheduler) return 0;
        ScanTask task;
        task.task_id = 1;
        task.file_path = virtual_name ? virtual_name : "in_memory_buffer";
        task.file_size = size;
        task.inline_data.assign(data, data + size);
        TaskScanReport rep = internal->scheduler->process_single_task(task);
        fill_c_result(rep, out_result);
        return 1;
    } catch (...) {
        return 0;
    }
}

void samulibre_gpu_request_cancel(SamulibreGPUContext ctx) {
    if (!ctx) return;
    try {
        auto* internal = static_cast<GPUContextInternal*>(ctx);
        if (internal->scheduler) {
            internal->scheduler->get_resource_monitor().request_cancellation();
        }
    } catch (...) {}
}

void samulibre_gpu_reset_cancel(SamulibreGPUContext ctx) {
    if (!ctx) return;
    try {
        auto* internal = static_cast<GPUContextInternal*>(ctx);
        if (internal->scheduler) {
            internal->scheduler->get_resource_monitor().reset_cancellation();
        }
    } catch (...) {}
}

int32_t samulibre_gpu_get_telemetry(SamulibreGPUContext ctx, SamulibreCTelemetry* out_telemetry) {
    if (!ctx || !out_telemetry) return 0;
    try {
        auto* internal = static_cast<GPUContextInternal*>(ctx);
        if (!internal->scheduler) return 0;
        ResourceSnapshot snap = internal->scheduler->get_resource_monitor().capture_snapshot();
        std::memset(out_telemetry, 0, sizeof(SamulibreCTelemetry));

        out_telemetry->gpu_temperature_c = snap.gpu_temperature_c;
        out_telemetry->gpu_power_watts = snap.gpu_power_watts;
        out_telemetry->vram_used_mb = snap.vram_used_mb;
        out_telemetry->vram_total_mb = snap.vram_total_mb;
        out_telemetry->ram_used_mb = snap.ram_used_mb;
        out_telemetry->system_load_1min = snap.system_load_1min;
        out_telemetry->is_throttled = snap.is_throttled ? 1 : 0;
        out_telemetry->is_gpu_accelerated = (internal->engine && internal->engine->is_gpu_accelerated()) ? 1 : 0;
        std::strncpy(out_telemetry->telemetry_source, snap.telemetry_source.c_str(), sizeof(out_telemetry->telemetry_source) - 1);
        return 1;
    } catch (...) {
        return 0;
    }
}

} // extern "C"
