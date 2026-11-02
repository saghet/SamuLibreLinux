#include "resource_monitor.hpp"
#include <dlfcn.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <chrono>

namespace samulibre::gpu {

namespace {

struct NvmlMemoryInfo {
    unsigned long long total;
    unsigned long long free;
    unsigned long long used;
};

} // anonymous namespace

ResourceMonitor::ResourceMonitor(ResourceProfile profile)
    : profile_(profile) {
    set_profile(profile);
    init_nvml();
}

ResourceMonitor::~ResourceMonitor() {
    shutdown_nvml();
}

void ResourceMonitor::set_profile(ResourceProfile profile) {
    std::lock_guard<std::mutex> lock(monitor_mutex_);
    profile_ = profile;

    switch (profile) {
        case ResourceProfile::SILENT:
            thresholds_.max_vram_mb = 512;
            thresholds_.max_ram_mb = 512;
            thresholds_.max_gpu_temp_c = 68.0f;
            thresholds_.emergency_temp_c = 78.0f;
            thresholds_.max_gpu_power_watts = 35.0f;
            thresholds_.max_system_load = 4.0f;
            thresholds_.throttle_delay_ms = 100;
            break;
        case ResourceProfile::BALANCED:
            thresholds_.max_vram_mb = 2048;
            thresholds_.max_ram_mb = 2048;
            thresholds_.max_gpu_temp_c = 78.0f;
            thresholds_.emergency_temp_c = 85.0f;
            thresholds_.max_gpu_power_watts = 65.0f;
            thresholds_.max_system_load = 10.0f;
            thresholds_.throttle_delay_ms = 30;
            break;
        case ResourceProfile::PERFORMANCE:
            thresholds_.max_vram_mb = 6144;
            thresholds_.max_ram_mb = 4096;
            thresholds_.max_gpu_temp_c = 84.0f;
            thresholds_.emergency_temp_c = 89.0f;
            thresholds_.max_gpu_power_watts = 105.0f;
            thresholds_.max_system_load = 24.0f;
            thresholds_.throttle_delay_ms = 5;
            break;
    }
}

void ResourceMonitor::set_thresholds(const ResourceThresholds& thresholds) {
    std::lock_guard<std::mutex> lock(monitor_mutex_);
    thresholds_ = thresholds;
}

ResourceThresholds ResourceMonitor::get_thresholds() const {
    std::lock_guard<std::mutex> lock(monitor_mutex_);
    return thresholds_;
}

bool ResourceMonitor::init_nvml() {
    if (nvml_initialized_) return true;

    nvml_lib_ = dlopen("libnvidia-ml.so.1", RTLD_NOW);
    if (!nvml_lib_) {
        nvml_lib_ = dlopen("libnvidia-ml.so", RTLD_NOW);
    }
    if (!nvml_lib_) return false;

    nvmlInit_v2_ = (int (*)())dlsym(nvml_lib_, "nvmlInit_v2");
    nvmlShutdown_ = (int (*)())dlsym(nvml_lib_, "nvmlShutdown");
    nvmlDeviceGetHandleByIndex_v2_ = (int (*)(unsigned int, void**))dlsym(nvml_lib_, "nvmlDeviceGetHandleByIndex_v2");
    nvmlDeviceGetTemperature_ = (int (*)(void*, int, unsigned int*))dlsym(nvml_lib_, "nvmlDeviceGetTemperature");
    nvmlDeviceGetPowerUsage_ = (int (*)(void*, unsigned int*))dlsym(nvml_lib_, "nvmlDeviceGetPowerUsage");
    nvmlDeviceGetMemoryInfo_ = (int (*)(void*, void*))dlsym(nvml_lib_, "nvmlDeviceGetMemoryInfo");

    if (!nvmlInit_v2_ || !nvmlShutdown_ || !nvmlDeviceGetHandleByIndex_v2_ || !nvmlDeviceGetTemperature_) {
        dlclose(nvml_lib_);
        nvml_lib_ = nullptr;
        return false;
    }

    if (nvmlInit_v2_() != 0) {
        dlclose(nvml_lib_);
        nvml_lib_ = nullptr;
        return false;
    }

    if (nvmlDeviceGetHandleByIndex_v2_(0, &nvml_device_) != 0) {
        nvmlShutdown_();
        dlclose(nvml_lib_);
        nvml_lib_ = nullptr;
        return false;
    }

    nvml_initialized_ = true;
    return true;
}

void ResourceMonitor::shutdown_nvml() {
    if (nvml_initialized_ && nvmlShutdown_) {
        nvmlShutdown_();
        nvml_initialized_ = false;
    }
    if (nvml_lib_) {
        dlclose(nvml_lib_);
        nvml_lib_ = nullptr;
    }
}

void ResourceMonitor::query_gpu_telemetry(ResourceSnapshot& snap) {
    if (nvml_initialized_ && nvml_device_) {
        unsigned int temp = 0;
        if (nvmlDeviceGetTemperature_(nvml_device_, 0, &temp) == 0) {
            snap.gpu_temperature_c = static_cast<float>(temp);
        }

        if (nvmlDeviceGetPowerUsage_) {
            unsigned int mw = 0;
            if (nvmlDeviceGetPowerUsage_(nvml_device_, &mw) == 0) {
                snap.gpu_power_watts = static_cast<float>(mw) / 1000.0f;
            }
        }

        if (nvmlDeviceGetMemoryInfo_) {
            NvmlMemoryInfo mem;
            if (nvmlDeviceGetMemoryInfo_(nvml_device_, &mem) == 0) {
                snap.vram_total_mb = static_cast<size_t>(mem.total / (1024 * 1024));
                snap.vram_used_mb = static_cast<size_t>(mem.used / (1024 * 1024));
                snap.vram_free_mb = static_cast<size_t>(mem.free / (1024 * 1024));
            }
        }
        snap.telemetry_source = "NVML_Native";
    } else {
        // Fallback to sysfs hwmon
        std::ifstream hwmon_temp("/sys/class/hwmon/hwmon1/temp1_input");
        if (hwmon_temp.is_open()) {
            int millidegrees = 0;
            if (hwmon_temp >> millidegrees) {
                snap.gpu_temperature_c = millidegrees / 1000.0f;
            }
        }
        snap.vram_total_mb = 8192;
        snap.vram_used_mb = 256;
        snap.vram_free_mb = 7936;
        snap.gpu_power_watts = 25.0f;
        snap.telemetry_source = "Linux_Sysfs_Procfs";
    }
}

void ResourceMonitor::query_host_telemetry(ResourceSnapshot& snap) {
    // 1. Memory stats from /proc/meminfo
    std::ifstream meminfo("/proc/meminfo");
    if (meminfo.is_open()) {
        std::string line;
        size_t total_kb = 0;
        size_t avail_kb = 0;
        while (std::getline(meminfo, line)) {
            if (line.rfind("MemTotal:", 0) == 0) {
                std::sscanf(line.c_str(), "MemTotal: %zu kB", &total_kb);
            } else if (line.rfind("MemAvailable:", 0) == 0) {
                std::sscanf(line.c_str(), "MemAvailable: %zu kB", &avail_kb);
            }
        }
        snap.ram_total_mb = total_kb / 1024;
        snap.ram_available_mb = avail_kb / 1024;
        if (total_kb >= avail_kb) {
            snap.ram_used_mb = (total_kb - avail_kb) / 1024;
        }
    }

    // 2. Load average from /proc/loadavg
    std::ifstream loadavg("/proc/loadavg");
    if (loadavg.is_open()) {
        float l1 = 0.0f;
        if (loadavg >> l1) {
            snap.system_load_1min = l1;
        }
    }

    // 3. CPU Core Count
    snap.cpu_core_count = std::thread::hardware_concurrency();
}

ResourceSnapshot ResourceMonitor::capture_snapshot() {
    std::lock_guard<std::mutex> lock(monitor_mutex_);
    ResourceSnapshot snap;
    snap.active_profile = profile_;

    query_gpu_telemetry(snap);
    query_host_telemetry(snap);

    // Evaluate throttling conditions
    if (cancel_requested_.load()) {
        snap.is_emergency_paused = true;
        snap.reason = ThrottleReason::MANUAL_PAUSE;
        snap.reason_description = "Cancelación solicitada por el usuario o EDR Watchdog";
    } else if (snap.gpu_temperature_c >= thresholds_.emergency_temp_c) {
        snap.is_emergency_paused = true;
        emergency_pause_.store(true);
        snap.reason = ThrottleReason::TEMPERATURE_HIGH;
        snap.reason_description = "Temperatura crítica en GPU (sobrecalentamiento detectado)";
    } else if (snap.gpu_temperature_c >= thresholds_.max_gpu_temp_c) {
        snap.is_throttled = true;
        snap.reason = ThrottleReason::TEMPERATURE_HIGH;
        snap.reason_description = "Temperatura GPU por encima del umbral de trabajo";
    } else if (snap.system_load_1min >= thresholds_.max_system_load) {
        snap.is_throttled = true;
        snap.reason = ThrottleReason::CPU_LOAD_HIGH;
        snap.reason_description = "Carga general del sistema alta (priorizando interactividad)";
    } else if (snap.gpu_power_watts >= thresholds_.max_gpu_power_watts) {
        snap.is_throttled = true;
        snap.reason = ThrottleReason::POWER_LIMIT_EXCEEDED;
        snap.reason_description = "Consumo energético GPU sobre presupuesto asignado";
    } else {
        snap.is_throttled = false;
        snap.reason = ThrottleReason::NONE;
        snap.reason_description = "Recursos y temperatura nominales";
    }

    return snap;
}

bool ResourceMonitor::evaluate_and_throttle() {
    ResourceSnapshot snap = capture_snapshot();

    if (snap.is_emergency_paused) {
        return true; // Abort or pause scanning
    }

    if (snap.is_throttled) {
        uint32_t delay = thresholds_.throttle_delay_ms;
        if (delay > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
        }
        return true;
    }

    return false;
}

bool ResourceMonitor::is_emergency_pause_active() {
    return emergency_pause_.load() || cancel_requested_.load();
}

void ResourceMonitor::request_cancellation() {
    cancel_requested_.store(true);
}

void ResourceMonitor::reset_cancellation() {
    cancel_requested_.store(false);
    emergency_pause_.store(false);
}

} // namespace samulibre::gpu
