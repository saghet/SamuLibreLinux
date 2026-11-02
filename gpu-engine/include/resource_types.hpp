#pragma once

#include "gpu_detector.hpp"
#include <string>
#include <cstdint>

namespace samulibre::gpu {

enum class ThrottleReason {
    NONE = 0,
    TEMPERATURE_HIGH = 1,
    VRAM_EXCEEDED = 2,
    RAM_EXCEEDED = 3,
    CPU_LOAD_HIGH = 4,
    POWER_LIMIT_EXCEEDED = 5,
    DEVICE_LOST = 6,
    MANUAL_PAUSE = 7
};

struct ResourceThresholds {
    size_t max_vram_mb = 2048;          // Max VRAM allowed for scanner
    size_t max_ram_mb = 2048;           // Max host RAM allowed for staging
    float max_gpu_temp_c = 78.0f;       // Temperature where throttling begins
    float emergency_temp_c = 85.0f;     // Critical temperature for emergency suspension
    float max_gpu_power_watts = 65.0f;  // Power draw budget
    float max_system_load = 8.0f;       // Load average threshold
    uint32_t throttle_delay_ms = 50;    // Pause duration during throttling
};

struct ResourceSnapshot {
    // GPU Telemetry
    float gpu_temperature_c = 0.0f;
    float gpu_power_watts = 0.0f;
    size_t vram_used_mb = 0;
    size_t vram_total_mb = 0;
    size_t vram_free_mb = 0;

    // Host System Telemetry
    size_t ram_used_mb = 0;
    size_t ram_total_mb = 0;
    size_t ram_available_mb = 0;
    float system_load_1min = 0.0f;
    uint32_t cpu_core_count = 0;

    // Control Status
    bool is_throttled = false;
    bool is_emergency_paused = false;
    ThrottleReason reason = ThrottleReason::NONE;
    std::string reason_description;
    ResourceProfile active_profile = ResourceProfile::BALANCED;
    std::string telemetry_source; // "NVML_Native" or "Linux_Sysfs_Procfs"
};

} // namespace samulibre::gpu
