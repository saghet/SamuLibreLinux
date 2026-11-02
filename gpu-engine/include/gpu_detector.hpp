#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace samulibre::gpu {

enum class BackendType {
    CUDA,
    OPENCL,
    VULKAN,
    CPU_FALLBACK
};

enum class GPUVendor {
    NVIDIA,
    AMD,
    INTEL,
    GENERIC_CPU
};

enum class ResourceProfile {
    SILENT,      // Low VRAM usage (<= 256MB), background priority
    BALANCED,    // Standard desktop usage (<= 1024MB), thermal control
    PERFORMANCE  // Maximum batch throughput (<= 4096MB)
};

struct GPUDeviceInfo {
    int device_id = -1;
    std::string name;
    GPUVendor vendor = GPUVendor::GENERIC_CPU;
    BackendType backend = BackendType::CPU_FALLBACK;
    uint64_t total_vram_bytes = 0;
    uint64_t free_vram_bytes = 0;
    uint32_t compute_units = 0;
    uint32_t clock_rate_khz = 0;
    int compute_capability_major = 0;
    int compute_capability_minor = 0;
    bool is_dedicated = false;
    bool supports_pinned_memory = false;
    bool supports_async_streams = false;
    float current_temperature_c = 0.0f;
};

class GPUDetector {
public:
    GPUDetector();
    ~GPUDetector();

    // Enumerate all available compute devices across CUDA, OpenCL and CPU Fallback
    std::vector<GPUDeviceInfo> enumerate_devices();

    // Select the optimal device according to the resource profile
    GPUDeviceInfo select_best_device(ResourceProfile profile = ResourceProfile::BALANCED);

    // Dynamic library availability checks
    bool has_cuda_driver() const;
    bool has_opencl_driver() const;
    bool has_vulkan_driver() const;

private:
    void probe_cuda_devices(std::vector<GPUDeviceInfo>& out_devices);
    void probe_opencl_devices(std::vector<GPUDeviceInfo>& out_devices);
    void add_cpu_fallback_device(std::vector<GPUDeviceInfo>& out_devices);

    bool cuda_driver_loaded_ = false;
    bool opencl_driver_loaded_ = false;
    bool vulkan_driver_loaded_ = false;

    void* cuda_lib_handle_ = nullptr;
    void* opencl_lib_handle_ = nullptr;
};

} // namespace samulibre::gpu
