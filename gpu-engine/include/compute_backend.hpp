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
};

} // namespace samulibre::gpu
