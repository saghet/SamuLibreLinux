#pragma once

#include "compute_backend.hpp"

namespace samulibre::gpu {

class CUDABackend : public IComputeBackend {
public:
    CUDABackend();
    ~CUDABackend() override;

    bool initialize(const GPUDeviceInfo& device) override;
    void shutdown() override;

    void* allocate_pinned_host(size_t bytes) override;
    void free_pinned_host(void* ptr) override;

    void* allocate_device_memory(size_t bytes) override;
    void free_device_memory(void* ptr) override;

    bool copy_host_to_device_async(void* dst_device, const void* src_host, size_t bytes, void* stream) override;
    bool copy_device_to_host_async(void* dst_host, const void* src_device, size_t bytes, void* stream) override;

    void* create_stream() override;
    void destroy_stream(void* stream) override;
    bool synchronize_stream(void* stream) override;
    bool synchronize_device() override;

    size_t get_free_vram_bytes() override;
    float get_gpu_temperature_c() override;
    const char* get_backend_name() const override { return "NVIDIA_CUDA_Native"; }
    BackendType get_backend_type() const override { return BackendType::CUDA; }

private:
    bool load_cuda_symbols();

    void* lib_handle_ = nullptr;
    int device_handle_ = 0;
    void* context_ = nullptr;
    bool initialized_ = false;

    // Function pointers loaded dynamically from libcuda.so.1
    int (*cuInit_)(unsigned int) = nullptr;
    int (*cuDeviceGet_)(int*, int) = nullptr;
    int (*cuCtxCreate_v2_)(void**, unsigned int, int) = nullptr;
    int (*cuCtxDestroy_v2_)(void*) = nullptr;
    int (*cuCtxSetCurrent_)(void*) = nullptr;
    int (*cuCtxSynchronize_)() = nullptr;
    int (*cuMemAlloc_v2_)(unsigned long long*, size_t) = nullptr;
    int (*cuMemFree_v2_)(unsigned long long) = nullptr;
    int (*cuMemAllocHost_v2_)(void**, size_t) = nullptr;
    int (*cuMemFreeHost_)(void*) = nullptr;
    int (*cuMemcpyHtoD_v2_)(unsigned long long, const void*, size_t) = nullptr;
    int (*cuMemcpyDtoH_v2_)(void*, unsigned long long, size_t) = nullptr;
    int (*cuMemcpyHtoDAsync_v2_)(unsigned long long, const void*, size_t, void*) = nullptr;
    int (*cuMemcpyDtoHAsync_v2_)(void*, unsigned long long, size_t, void*) = nullptr;
    int (*cuStreamCreate_)(void**, unsigned int) = nullptr;
    int (*cuStreamDestroy_v2_)(void*) = nullptr;
    int (*cuStreamSynchronize_)(void*) = nullptr;
    int (*cuMemGetInfo_v2_)(size_t*, size_t*) = nullptr;
};

} // namespace samulibre::gpu
