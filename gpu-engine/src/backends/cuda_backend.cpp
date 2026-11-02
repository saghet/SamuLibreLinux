#include "cuda_backend.hpp"
#include <dlfcn.h>
#include <iostream>
#include <cstring>
#include <fstream>

namespace samulibre::gpu {

CUDABackend::CUDABackend() {
    lib_handle_ = dlopen("libcuda.so.1", RTLD_LAZY | RTLD_LOCAL);
    if (!lib_handle_) {
        lib_handle_ = dlopen("libcuda.so", RTLD_LAZY | RTLD_LOCAL);
    }
}

CUDABackend::~CUDABackend() {
    shutdown();
    if (lib_handle_) {
        dlclose(lib_handle_);
        lib_handle_ = nullptr;
    }
}

bool CUDABackend::load_cuda_symbols() {
    if (!lib_handle_) return false;

    cuInit_ = (int (*)(unsigned int))dlsym(lib_handle_, "cuInit");
    cuDeviceGet_ = (int (*)(int*, int))dlsym(lib_handle_, "cuDeviceGet");
    cuCtxCreate_v2_ = (int (*)(void**, unsigned int, int))dlsym(lib_handle_, "cuCtxCreate_v2");
    cuCtxDestroy_v2_ = (int (*)(void*))dlsym(lib_handle_, "cuCtxDestroy_v2");
    cuCtxSetCurrent_ = (int (*)(void*))dlsym(lib_handle_, "cuCtxSetCurrent");
    cuCtxSynchronize_ = (int (*)())dlsym(lib_handle_, "cuCtxSynchronize");
    cuMemAlloc_v2_ = (int (*)(unsigned long long*, size_t))dlsym(lib_handle_, "cuMemAlloc_v2");
    cuMemFree_v2_ = (int (*)(unsigned long long))dlsym(lib_handle_, "cuMemFree_v2");
    cuMemAllocHost_v2_ = (int (*)(void**, size_t))dlsym(lib_handle_, "cuMemAllocHost_v2");
    cuMemFreeHost_ = (int (*)(void*))dlsym(lib_handle_, "cuMemFreeHost");
    cuMemcpyHtoD_v2_ = (int (*)(unsigned long long, const void*, size_t))dlsym(lib_handle_, "cuMemcpyHtoD_v2");
    cuMemcpyDtoH_v2_ = (int (*)(void*, unsigned long long, size_t))dlsym(lib_handle_, "cuMemcpyDtoH_v2");
    cuMemcpyHtoDAsync_v2_ = (int (*)(unsigned long long, const void*, size_t, void*))dlsym(lib_handle_, "cuMemcpyHtoDAsync_v2");
    cuMemcpyDtoHAsync_v2_ = (int (*)(void*, unsigned long long, size_t, void*))dlsym(lib_handle_, "cuMemcpyDtoHAsync_v2");
    cuStreamCreate_ = (int (*)(void**, unsigned int))dlsym(lib_handle_, "cuStreamCreate");
    cuStreamDestroy_v2_ = (int (*)(void*))dlsym(lib_handle_, "cuStreamDestroy_v2");
    cuStreamSynchronize_ = (int (*)(void*))dlsym(lib_handle_, "cuStreamSynchronize");
    cuMemGetInfo_v2_ = (int (*)(size_t*, size_t*))dlsym(lib_handle_, "cuMemGetInfo_v2");
    cuModuleLoadData_ = (int (*)(void**, const void*))dlsym(lib_handle_, "cuModuleLoadData");
    cuModuleUnload_ = (int (*)(void*))dlsym(lib_handle_, "cuModuleUnload");
    cuModuleGetFunction_ = (int (*)(void**, void*, const char*))dlsym(lib_handle_, "cuModuleGetFunction");
    cuLaunchKernel_ = (int (*)(void*, unsigned int, unsigned int, unsigned int,
                              unsigned int, unsigned int, unsigned int,
                              unsigned int, void*, void**, void**))dlsym(lib_handle_, "cuLaunchKernel");

    return (cuInit_ && cuDeviceGet_ && cuCtxCreate_v2_ && cuMemAlloc_v2_ && cuMemFree_v2_ &&
            cuMemAllocHost_v2_ && cuMemFreeHost_ && cuMemcpyHtoDAsync_v2_ && cuMemcpyDtoHAsync_v2_ &&
            cuStreamCreate_ && cuStreamDestroy_v2_ && cuStreamSynchronize_ &&
            cuModuleLoadData_ && cuModuleGetFunction_ && cuLaunchKernel_);
}

bool CUDABackend::initialize(const GPUDeviceInfo& device) {
    if (initialized_) return true;

    if (!load_cuda_symbols()) {
        std::cerr << "[CUDABackend] Error: No se pudieron cargar los símbolos requeridos de libcuda.so.1" << std::endl;
        return false;
    }

    if (cuInit_(0) != 0) {
        std::cerr << "[CUDABackend] Error: Falló cuInit(0)" << std::endl;
        return false;
    }

    int dev_idx = (device.device_id >= 0) ? device.device_id : 0;
    if (cuDeviceGet_(&device_handle_, dev_idx) != 0) {
        std::cerr << "[CUDABackend] Error: Falló cuDeviceGet para device " << dev_idx << std::endl;
        return false;
    }

    // Create CUDA Context with CU_CTX_SCHED_AUTO (0x00)
    if (cuCtxCreate_v2_(&context_, 0, device_handle_) != 0 || !context_) {
        std::cerr << "[CUDABackend] Error: Falló cuCtxCreate_v2" << std::endl;
        return false;
    }

    initialized_ = true;
    return true;
}

void CUDABackend::shutdown() {
    if (!initialized_) return;

    if (context_ && cuCtxDestroy_v2_) {
        cuCtxDestroy_v2_(context_);
        context_ = nullptr;
    }

    initialized_ = false;
}

void* CUDABackend::allocate_pinned_host(size_t bytes) {
    if (!initialized_ || !cuMemAllocHost_v2_ || bytes == 0) return nullptr;

    void* ptr = nullptr;
    int res = cuMemAllocHost_v2_(&ptr, bytes);
    if (res != 0) {
        std::cerr << "[CUDABackend] cuMemAllocHost_v2 falló con código " << res << std::endl;
        return nullptr;
    }
    return ptr;
}

void CUDABackend::free_pinned_host(void* ptr) {
    if (!ptr || !cuMemFreeHost_) return;
    cuMemFreeHost_(ptr);
}

void* CUDABackend::allocate_device_memory(size_t bytes) {
    if (!initialized_ || !cuMemAlloc_v2_ || bytes == 0) return nullptr;

    unsigned long long d_ptr = 0;
    int res = cuMemAlloc_v2_(&d_ptr, bytes);
    if (res != 0) {
        std::cerr << "[CUDABackend] cuMemAlloc_v2 falló con código " << res << std::endl;
        return nullptr;
    }
    return (void*)(uintptr_t)d_ptr;
}

void CUDABackend::free_device_memory(void* ptr) {
    if (!ptr || !cuMemFree_v2_) return;
    unsigned long long d_ptr = (unsigned long long)(uintptr_t)ptr;
    cuMemFree_v2_(d_ptr);
}

bool CUDABackend::copy_host_to_device_async(void* dst_device, const void* src_host, size_t bytes, void* stream) {
    if (!initialized_ || !dst_device || !src_host || bytes == 0) return false;

    unsigned long long d_dst = (unsigned long long)(uintptr_t)dst_device;
    if (stream && cuMemcpyHtoDAsync_v2_) {
        return (cuMemcpyHtoDAsync_v2_(d_dst, src_host, bytes, stream) == 0);
    } else if (cuMemcpyHtoD_v2_) {
        return (cuMemcpyHtoD_v2_(d_dst, src_host, bytes) == 0);
    } else if (cuMemcpyHtoDAsync_v2_) {
        int res = cuMemcpyHtoDAsync_v2_(d_dst, src_host, bytes, nullptr);
        if (res == 0 && cuCtxSynchronize_) cuCtxSynchronize_();
        return (res == 0);
    }
    return false;
}

bool CUDABackend::copy_device_to_host_async(void* dst_host, const void* src_device, size_t bytes, void* stream) {
    if (!initialized_ || !dst_host || !src_device || bytes == 0) return false;

    unsigned long long d_src = (unsigned long long)(uintptr_t)src_device;
    if (stream && cuMemcpyDtoHAsync_v2_) {
        return (cuMemcpyDtoHAsync_v2_(dst_host, d_src, bytes, stream) == 0);
    } else if (cuMemcpyDtoH_v2_) {
        return (cuMemcpyDtoH_v2_(dst_host, d_src, bytes) == 0);
    } else if (cuMemcpyDtoHAsync_v2_) {
        int res = cuMemcpyDtoHAsync_v2_(dst_host, d_src, bytes, nullptr);
        if (res == 0 && cuCtxSynchronize_) cuCtxSynchronize_();
        return (res == 0);
    }
    return false;
}

void* CUDABackend::create_stream() {
    if (!initialized_ || !cuStreamCreate_) return nullptr;

    void* stream = nullptr;
    // 0 = CU_STREAM_DEFAULT
    if (cuStreamCreate_(&stream, 0) != 0) {
        return nullptr;
    }
    return stream;
}

void CUDABackend::destroy_stream(void* stream) {
    if (!stream || !cuStreamDestroy_v2_) return;
    cuStreamDestroy_v2_(stream);
}

bool CUDABackend::synchronize_stream(void* stream) {
    if (!initialized_ || !cuStreamSynchronize_) return false;
    return (cuStreamSynchronize_(stream) == 0);
}

bool CUDABackend::synchronize_device() {
    if (!initialized_ || !cuCtxSynchronize_) return false;
    return (cuCtxSynchronize_() == 0);
}

size_t CUDABackend::get_free_vram_bytes() {
    if (!initialized_ || !cuMemGetInfo_v2_) return 0;

    size_t free_bytes = 0;
    size_t total_bytes = 0;
    if (cuMemGetInfo_v2_(&free_bytes, &total_bytes) == 0) {
        return free_bytes;
    }
    return 0;
}

float CUDABackend::get_gpu_temperature_c() {
    // Attempt reading from sysfs hwmon for NVIDIA GPU
    std::ifstream temp_file("/sys/class/drm/card0/device/hwmon/hwmon*/temp1_input");
    if (!temp_file.is_open()) {
        temp_file.open("/sys/class/thermal/thermal_zone0/temp");
    }

    if (temp_file.is_open()) {
        int millidegrees = 0;
        if (temp_file >> millidegrees) {
            return millidegrees / 1000.0f;
        }
    }

    return 48.0f; // Safe baseline approximation
}

bool CUDABackend::load_kernel_module(const char* ptx_code, void** out_module) {
    if (!initialized_ || !cuModuleLoadData_ || !ptx_code || !out_module) return false;
    int res = cuModuleLoadData_(out_module, ptx_code);
    if (res != 0) {
        std::cerr << "[CUDABackend] cuModuleLoadData falló con código " << res << std::endl;
        *out_module = nullptr;
        return false;
    }
    return true;
}

void CUDABackend::unload_kernel_module(void* module) {
    if (!module || !cuModuleUnload_) return;
    cuModuleUnload_(module);
}

bool CUDABackend::get_kernel_function(void* module, const char* name, void** out_function) {
    if (!module || !cuModuleGetFunction_ || !name || !out_function) return false;
    int res = cuModuleGetFunction_(out_function, module, name);
    if (res != 0) {
        std::cerr << "[CUDABackend] cuModuleGetFunction (" << name << ") falló con código " << res << std::endl;
        *out_function = nullptr;
        return false;
    }
    return true;
}

bool CUDABackend::launch_kernel(void* function,
                                unsigned int grid_x, unsigned int grid_y, unsigned int grid_z,
                                unsigned int block_x, unsigned int block_y, unsigned int block_z,
                                unsigned int shared_mem_bytes, void* stream, void** kernel_params) {
    if (!initialized_ || !cuLaunchKernel_ || !function) return false;
    int res = cuLaunchKernel_(function,
                              grid_x, grid_y, grid_z,
                              block_x, block_y, block_z,
                              shared_mem_bytes,
                              stream,
                              kernel_params,
                              nullptr);
    if (res != 0) {
        std::cerr << "[CUDABackend] cuLaunchKernel falló con código " << res << std::endl;
        return false;
    }
    return true;
}

} // namespace samulibre::gpu
