#pragma once

#include "compute_backend.hpp"
#include <vector>
#include <mutex>

namespace samulibre::gpu {

class CPUFallbackBackend : public IComputeBackend {
public:
    CPUFallbackBackend();
    ~CPUFallbackBackend() override;

    bool initialize(const GPUDeviceInfo& device) override;
    void shutdown() override;

    void* allocate_pinned_host(size_t bytes) override;
    void free_pinned_host(void* ptr) override;

    void* allocate_device_memory(size_t bytes) override;
    void free_device_memory(void* ptr) override;

    bool copy_host_to_device_async(void* dst_device, const void* src_host, size_t bytes, void* stream) override;
    virtual bool copy_device_to_host_async(void* dst_host, const void* src_device, size_t bytes, void* stream) override;

    void* create_stream() override;
    void destroy_stream(void* stream) override;
    bool synchronize_stream(void* stream) override;
    bool synchronize_device() override;

    size_t get_free_vram_bytes() override;
    float get_gpu_temperature_c() override;
    const char* get_backend_name() const override { return "CPU_Fallback_AVX2"; }
    BackendType get_backend_type() const override { return BackendType::CPU_FALLBACK; }

private:
    bool initialized_ = false;
    std::mutex alloc_mutex_;
    size_t allocated_bytes_ = 0;
};

} // namespace samulibre::gpu
