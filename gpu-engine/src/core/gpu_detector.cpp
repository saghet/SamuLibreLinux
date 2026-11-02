#include "gpu_detector.hpp"
#include <dlfcn.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <thread>

namespace samulibre::gpu {

GPUDetector::GPUDetector() {
    // 1. Probe for NVIDIA CUDA Driver Library
    cuda_lib_handle_ = dlopen("libcuda.so.1", RTLD_LAZY | RTLD_LOCAL);
    if (!cuda_lib_handle_) {
        cuda_lib_handle_ = dlopen("libcuda.so", RTLD_LAZY | RTLD_LOCAL);
    }
    cuda_driver_loaded_ = (cuda_lib_handle_ != nullptr);

    // 2. Probe for OpenCL ICD Loader
    opencl_lib_handle_ = dlopen("libOpenCL.so.1", RTLD_LAZY | RTLD_LOCAL);
    if (!opencl_lib_handle_) {
        opencl_lib_handle_ = dlopen("libOpenCL.so", RTLD_LAZY | RTLD_LOCAL);
    }
    opencl_driver_loaded_ = (opencl_lib_handle_ != nullptr);

    // 3. Probe for Vulkan Loader
    void* vk_handle = dlopen("libvulkan.so.1", RTLD_LAZY | RTLD_LOCAL);
    vulkan_driver_loaded_ = (vk_handle != nullptr);
    if (vk_handle) {
        dlclose(vk_handle);
    }
}

GPUDetector::~GPUDetector() {
    if (cuda_lib_handle_) {
        dlclose(cuda_lib_handle_);
        cuda_lib_handle_ = nullptr;
    }
    if (opencl_lib_handle_) {
        dlclose(opencl_lib_handle_);
        opencl_lib_handle_ = nullptr;
    }
}

bool GPUDetector::has_cuda_driver() const {
    return cuda_driver_loaded_;
}

bool GPUDetector::has_opencl_driver() const {
    return opencl_driver_loaded_;
}

bool GPUDetector::has_vulkan_driver() const {
    return vulkan_driver_loaded_;
}

void GPUDetector::probe_cuda_devices(std::vector<GPUDeviceInfo>& out_devices) {
    if (!cuda_lib_handle_) return;

    typedef int (*cuInit_t)(unsigned int);
    typedef int (*cuDeviceGetCount_t)(int*);
    typedef int (*cuDeviceGet_t)(int*, int);
    typedef int (*cuDeviceGetName_t)(char*, int, int);
    typedef int (*cuDeviceTotalMem_t)(size_t*, int);
    typedef int (*cuDeviceGetAttribute_t)(int*, int, int);

    auto cuInit_fn = (cuInit_t)dlsym(cuda_lib_handle_, "cuInit");
    auto cuDeviceGetCount_fn = (cuDeviceGetCount_t)dlsym(cuda_lib_handle_, "cuDeviceGetCount");
    auto cuDeviceGet_fn = (cuDeviceGet_t)dlsym(cuda_lib_handle_, "cuDeviceGet");
    auto cuDeviceGetName_fn = (cuDeviceGetName_t)dlsym(cuda_lib_handle_, "cuDeviceGetName");
    auto cuDeviceTotalMem_fn = (cuDeviceTotalMem_t)dlsym(cuda_lib_handle_, "cuDeviceTotalMem_v2");
    if (!cuDeviceTotalMem_fn) {
        cuDeviceTotalMem_fn = (cuDeviceTotalMem_t)dlsym(cuda_lib_handle_, "cuDeviceTotalMem");
    }
    auto cuDeviceGetAttribute_fn = (cuDeviceGetAttribute_t)dlsym(cuda_lib_handle_, "cuDeviceGetAttribute");

    if (!cuInit_fn || !cuDeviceGetCount_fn || !cuDeviceGet_fn || !cuDeviceGetName_fn) {
        return;
    }

    if (cuInit_fn(0) != 0) {
        return;
    }

    int count = 0;
    if (cuDeviceGetCount_fn(&count) != 0 || count <= 0) {
        return;
    }

    for (int i = 0; i < count; ++i) {
        int dev = 0;
        if (cuDeviceGet_fn(&dev, i) != 0) continue;

        char name[256] = {0};
        cuDeviceGetName_fn(name, sizeof(name) - 1, dev);

        size_t total_mem = 0;
        if (cuDeviceTotalMem_fn) {
            cuDeviceTotalMem_fn(&total_mem, dev);
        }

        GPUDeviceInfo info;
        info.device_id = i;
        info.name = name;
        info.vendor = GPUVendor::NVIDIA;
        info.backend = BackendType::CUDA;
        info.total_vram_bytes = total_mem;
        info.free_vram_bytes = total_mem; // Will be queried live during execution
        info.is_dedicated = true;
        info.supports_pinned_memory = true;
        info.supports_async_streams = true;

        if (cuDeviceGetAttribute_fn) {
            int major = 0, minor = 0, sm_count = 0, clock = 0;
            // 75 = CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR
            cuDeviceGetAttribute_fn(&major, 75, dev);
            // 76 = CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR
            cuDeviceGetAttribute_fn(&minor, 76, dev);
            // 16 = CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT
            cuDeviceGetAttribute_fn(&sm_count, 16, dev);
            // 13 = CU_DEVICE_ATTRIBUTE_CLOCK_RATE
            cuDeviceGetAttribute_fn(&clock, 13, dev);

            info.compute_capability_major = major;
            info.compute_capability_minor = minor;
            info.compute_units = sm_count;
            info.clock_rate_khz = clock;
        }

        out_devices.push_back(info);
    }
}

void GPUDetector::probe_opencl_devices(std::vector<GPUDeviceInfo>& out_devices) {
    if (!opencl_lib_handle_) return;

    typedef int (*clGetPlatformIDs_t)(uint32_t, void**, uint32_t*);
    typedef int (*clGetDeviceIDs_t)(void*, uint64_t, uint32_t, void**, uint32_t*);
    typedef int (*clGetDeviceInfo_t)(void*, uint32_t, size_t, void*, size_t*);

    auto clGetPlatformIDs_fn = (clGetPlatformIDs_t)dlsym(opencl_lib_handle_, "clGetPlatformIDs");
    auto clGetDeviceIDs_fn = (clGetDeviceIDs_t)dlsym(opencl_lib_handle_, "clGetDeviceIDs");
    auto clGetDeviceInfo_fn = (clGetDeviceInfo_t)dlsym(opencl_lib_handle_, "clGetDeviceInfo");

    if (!clGetPlatformIDs_fn || !clGetDeviceIDs_fn || !clGetDeviceInfo_fn) {
        return;
    }

    uint32_t num_platforms = 0;
    if (clGetPlatformIDs_fn(0, nullptr, &num_platforms) != 0 || num_platforms == 0) {
        return;
    }

    std::vector<void*> platforms(num_platforms);
    clGetPlatformIDs_fn(num_platforms, platforms.data(), nullptr);

    int dev_idx = 0;
    for (void* platform : platforms) {
        uint32_t num_cl_devices = 0;
        // 0xFFFFFFFF = CL_DEVICE_TYPE_ALL
        if (clGetDeviceIDs_fn(platform, 0xFFFFFFFF, 0, nullptr, &num_cl_devices) != 0 || num_cl_devices == 0) {
            continue;
        }

        std::vector<void*> cl_devices(num_cl_devices);
        clGetDeviceIDs_fn(platform, 0xFFFFFFFF, num_cl_devices, cl_devices.data(), nullptr);

        for (void* cl_dev : cl_devices) {
            char dev_name[256] = {0};
            // 0x102B = CL_DEVICE_NAME
            clGetDeviceInfo_fn(cl_dev, 0x102B, sizeof(dev_name) - 1, dev_name, nullptr);

            uint64_t global_mem = 0;
            // 0x101F = CL_DEVICE_GLOBAL_MEM_SIZE
            clGetDeviceInfo_fn(cl_dev, 0x101F, sizeof(global_mem), &global_mem, nullptr);

            uint32_t max_compute_units = 0;
            // 0x1002 = CL_DEVICE_MAX_COMPUTE_UNITS
            clGetDeviceInfo_fn(cl_dev, 0x1002, sizeof(max_compute_units), &max_compute_units, nullptr);

            uint64_t dev_type = 0;
            // 0x1000 = CL_DEVICE_TYPE
            clGetDeviceInfo_fn(cl_dev, 0x1000, sizeof(dev_type), &dev_type, nullptr);

            // Avoid duplicating NVIDIA device if already enumerated via native CUDA
            std::string name_str(dev_name);
            bool already_added = false;
            for (const auto& existing : out_devices) {
                if (existing.name == name_str) {
                    already_added = true;
                    break;
                }
            }
            if (already_added) continue;

            GPUDeviceInfo info;
            info.device_id = dev_idx++;
            info.name = name_str;
            info.backend = BackendType::OPENCL;
            info.total_vram_bytes = global_mem;
            info.free_vram_bytes = global_mem;
            info.compute_units = max_compute_units;
            // 0x0004 = CL_DEVICE_TYPE_GPU
            info.is_dedicated = (dev_type & 0x0004) != 0;
            info.supports_pinned_memory = true;
            info.supports_async_streams = true;

            if (name_str.find("AMD") != std::string::npos || name_str.find("Radeon") != std::string::npos) {
                info.vendor = GPUVendor::AMD;
            } else if (name_str.find("Intel") != std::string::npos) {
                info.vendor = GPUVendor::INTEL;
            } else if (name_str.find("NVIDIA") != std::string::npos) {
                info.vendor = GPUVendor::NVIDIA;
            } else {
                info.vendor = GPUVendor::GENERIC_CPU;
            }

            out_devices.push_back(info);
        }
    }
}

void GPUDetector::add_cpu_fallback_device(std::vector<GPUDeviceInfo>& out_devices) {
    GPUDeviceInfo cpu_info;
    cpu_info.device_id = -1;
    cpu_info.name = "Host CPU Multi-Core (AVX2 / SIMD Fallback)";
    cpu_info.vendor = GPUVendor::GENERIC_CPU;
    cpu_info.backend = BackendType::CPU_FALLBACK;
    cpu_info.compute_units = std::thread::hardware_concurrency();
    cpu_info.is_dedicated = false;
    cpu_info.supports_pinned_memory = false;
    cpu_info.supports_async_streams = true;

    // Estimate available host RAM from /proc/meminfo
    std::ifstream meminfo("/proc/meminfo");
    std::string line;
    uint64_t mem_total_kb = 0;
    while (std::getline(meminfo, line)) {
        if (line.rfind("MemTotal:", 0) == 0) {
            std::istringstream iss(line.substr(9));
            iss >> mem_total_kb;
            break;
        }
    }
    cpu_info.total_vram_bytes = mem_total_kb * 1024;
    cpu_info.free_vram_bytes = cpu_info.total_vram_bytes / 2;

    out_devices.push_back(cpu_info);
}

std::vector<GPUDeviceInfo> GPUDetector::enumerate_devices() {
    std::vector<GPUDeviceInfo> devices;

    // 1. Native CUDA Driver
    probe_cuda_devices(devices);

    // 2. OpenCL Platforms (AMD / Intel / Mesa RADV)
    probe_opencl_devices(devices);

    // 3. Guaranteed CPU Fallback
    add_cpu_fallback_device(devices);

    return devices;
}

GPUDeviceInfo GPUDetector::select_best_device(ResourceProfile profile) {
    std::vector<GPUDeviceInfo> devices = enumerate_devices();

    // In SILENT profile: if low-power desktop background scanning is desired without spinning GPU fans
    if (profile == ResourceProfile::SILENT) {
        // Look for iGPU first (OpenCL integrated) to minimize power and fan noise
        for (const auto& dev : devices) {
            if (dev.backend == BackendType::OPENCL && !dev.is_dedicated) {
                return dev;
            }
        }
    }

    // Default & PERFORMANCE: Priority to high-throughput dedicated hardware
    // 1. Dedicated NVIDIA GPU with CUDA
    for (const auto& dev : devices) {
        if (dev.backend == BackendType::CUDA && dev.is_dedicated) {
            return dev;
        }
    }

    // 2. OpenCL GPU (AMD Radeon / Intel Arc)
    for (const auto& dev : devices) {
        if (dev.backend == BackendType::OPENCL && dev.is_dedicated) {
            return dev;
        }
    }

    // 3. Integrated OpenCL GPU
    for (const auto& dev : devices) {
        if (dev.backend == BackendType::OPENCL) {
            return dev;
        }
    }

    // 4. Safe CPU Fallback
    return devices.back();
}

} // namespace samulibre::gpu
