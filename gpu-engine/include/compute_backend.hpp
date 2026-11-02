#pragma once

#include "gpu_detector.hpp"
#include <cstddef>
#include <cstdint>
#include <string>

namespace samulibre::gpu {

// Device memory buffer descriptor
struct DeviceBuffer {
    void* ptr = nullptr;
    size_t size_bytes = 0;
    bool is_pinned = false;
    BackendType backend = BackendType::CPU_FALLBACK;
};

// Abstract interface for all hardware compute backends
class IComputeBackend {
public:
    virtual ~IComputeBackend() = default;

    virtual bool initialize(const GPUDeviceInfo& device) = 0;
    virtual void shutdown() = 0;

    // Memory Allocation & Pinned Host Memory (PCIe Transfer Optimization)
    virtual void* allocate_pinned_host(size_t bytes) = 0;
    virtual void free_pinned_host(void* ptr) = 0;

    virtual void* allocate_device_memory(size_t bytes) = 0;
    virtual void free_device_memory(void* ptr) = 0;

    // Asynchronous PCIe Transfers
    virtual bool copy_host_to_device_async(void* dst_device, const void* src_host, size_t bytes, void* stream) = 0;
    virtual bool copy_device_to_host_async(void* dst_host, const void* src_device, size_t bytes, void* stream) = 0;

    // Streams and Synchronization
    virtual void* create_stream() = 0;
    virtual void destroy_stream(void* stream) = 0;
    virtual bool synchronize_stream(void* stream) = 0;
    virtual bool synchronize_device() = 0;

    // Telemetry and Health
    virtual size_t get_free_vram_bytes() = 0;
    virtual float get_gpu_temperature_c() = 0;
    virtual const char* get_backend_name() const = 0;
    virtual BackendType get_backend_type() const = 0;

    // Custom Kernel Execution (GPU Native)
    virtual bool supports_custom_kernels() const { return false; }
    virtual bool load_kernel_module(const char* ptx_code, void** out_module) { 
        (void)ptx_code; (void)out_module; return false; 
    }
    virtual void unload_kernel_module(void* module) { 
        (void)module; 
    }
    virtual bool get_kernel_function(void* module, const char* name, void** out_function) { 
        (void)module; (void)name; (void)out_function; return false; 
    }
    virtual bool launch_kernel(void* function,
                               unsigned int grid_x, unsigned int grid_y, unsigned int grid_z,
                               unsigned int block_x, unsigned int block_y, unsigned int block_z,
                               unsigned int shared_mem_bytes, void* stream, void** kernel_params) {
        (void)function; (void)grid_x; (void)grid_y; (void)grid_z;
        (void)block_x; (void)block_y; (void)block_z;
        (void)shared_mem_bytes; (void)stream; (void)kernel_params;
        return false;
    }
};

} // namespace samulibre::gpu
