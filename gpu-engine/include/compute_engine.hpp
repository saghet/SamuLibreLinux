#pragma once

#include "gpu_detector.hpp"
#include "compute_backend.hpp"
#include <memory>
#include <string>

namespace samulibre::gpu {

class GPUComputeEngine {
public:
    explicit GPUComputeEngine(ResourceProfile profile = ResourceProfile::BALANCED);
    ~GPUComputeEngine();

    // Automatically detect hardware, initialize optimal backend (CUDA -> OpenCL -> CPU Fallback)
    bool initialize();
    void shutdown();

    // Query active state
    bool is_gpu_accelerated() const;
    std::string get_active_backend_name() const;
    const GPUDeviceInfo& get_active_device_info() const;
    ResourceProfile get_resource_profile() const { return profile_; }

    // Memory buffer lifecycle through active backend
    void* allocate_host_buffer(size_t bytes);
    void free_host_buffer(void* ptr);

    void* allocate_device_buffer(size_t bytes);
    void free_device_buffer(void* ptr);

    bool transfer_to_device(void* dst_device, const void* src_host, size_t bytes, void* stream = nullptr);
    bool transfer_to_host(void* dst_host, const void* src_device, size_t bytes, void* stream = nullptr);
    bool synchronize();

    // Fallback trigger (called on unrecoverable GPU driver error)
    void force_fallback_to_cpu(const std::string& reason);

    // Custom Kernel Execution Delegation
    bool supports_custom_kernels() const { return backend_ && backend_->supports_custom_kernels(); }
    bool load_kernel_module(const char* ptx_code, void** out_module) {
        return backend_ ? backend_->load_kernel_module(ptx_code, out_module) : false;
    }
    void unload_kernel_module(void* module) {
        if (backend_) backend_->unload_kernel_module(module);
    }
    bool get_kernel_function(void* module, const char* name, void** out_function) {
        return backend_ ? backend_->get_kernel_function(module, name, out_function) : false;
    }
    bool launch_kernel(void* function,
                       unsigned int grid_x, unsigned int grid_y, unsigned int grid_z,
                       unsigned int block_x, unsigned int block_y, unsigned int block_z,
                       unsigned int shared_mem_bytes, void* stream, void** kernel_params) {
        return backend_ ? backend_->launch_kernel(function, grid_x, grid_y, grid_z, block_x, block_y, block_z, shared_mem_bytes, stream, kernel_params) : false;
    }

    // Raw backend access
    IComputeBackend* get_raw_backend() const { return backend_.get(); }

private:
    ResourceProfile profile_;
    GPUDetector detector_;
    GPUDeviceInfo active_device_;
    std::unique_ptr<IComputeBackend> backend_;
    bool is_initialized_ = false;
    bool fallback_triggered_ = false;
};

} // namespace samulibre::gpu
