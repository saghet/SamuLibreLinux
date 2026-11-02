#pragma once

#include "resource_types.hpp"
#include <mutex>
#include <atomic>
#include <memory>

namespace samulibre::gpu {

class ResourceMonitor {
public:
    explicit ResourceMonitor(ResourceProfile profile = ResourceProfile::BALANCED);
    ~ResourceMonitor();

    // Profile and Threshold configuration
    void set_profile(ResourceProfile profile);
    ResourceProfile get_profile() const { return profile_; }

    void set_thresholds(const ResourceThresholds& thresholds);
    ResourceThresholds get_thresholds() const;

    // Real-time telemetry snapshot
    ResourceSnapshot capture_snapshot();

    // Dynamic Control & Throttling
    // Evaluates current hardware state: if throttled, performs safe delay and returns true.
    bool evaluate_and_throttle();

    // Emergency circuit breaker: if true, hardware is in unsafe condition (> 85 C or fatal VRAM exhaustion)
    bool is_emergency_pause_active();

    // Cancellation token for safe cooperative task cancellation
    void request_cancellation();
    void reset_cancellation();
    bool is_cancellation_requested() const { return cancel_requested_.load(); }

private:
    bool init_nvml();
    void shutdown_nvml();

    void query_gpu_telemetry(ResourceSnapshot& snap);
    void query_host_telemetry(ResourceSnapshot& snap);

    ResourceProfile profile_;
    ResourceThresholds thresholds_;
    mutable std::mutex monitor_mutex_;

    std::atomic<bool> cancel_requested_{false};
    std::atomic<bool> emergency_pause_{false};

    // NVML dynamic loader resources
    void* nvml_lib_ = nullptr;
    void* nvml_device_ = nullptr;
    bool nvml_initialized_ = false;

    // Function pointers loaded dynamically from libnvidia-ml.so.1
    int (*nvmlInit_v2_)() = nullptr;
    int (*nvmlShutdown_)() = nullptr;
    int (*nvmlDeviceGetHandleByIndex_v2_)(unsigned int, void**) = nullptr;
    int (*nvmlDeviceGetTemperature_)(void*, int, unsigned int*) = nullptr;
    int (*nvmlDeviceGetPowerUsage_)(void*, unsigned int*) = nullptr;
    int (*nvmlDeviceGetMemoryInfo_)(void*, void*) = nullptr;
};

} // namespace samulibre::gpu
