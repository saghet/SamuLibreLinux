#include "cpu_fallback.hpp"
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>

namespace samulibre::gpu {

CPUFallbackBackend::CPUFallbackBackend() = default;

CPUFallbackBackend::~CPUFallbackBackend() {
    shutdown();
}

bool CPUFallbackBackend::initialize(const GPUDeviceInfo& /*device*/) {
    initialized_ = true;
    return true;
}

void CPUFallbackBackend::shutdown() {
    initialized_ = false;
}

void* CPUFallbackBackend::allocate_pinned_host(size_t bytes) {
    if (bytes == 0) return nullptr;

    void* ptr = nullptr;
    // 64-byte alignment optimizes for AVX2 and AVX-512 cache lines
    if (posix_memalign(&ptr, 64, bytes) != 0) {
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(alloc_mutex_);
    allocated_bytes_ += bytes;
    return ptr;
}

void CPUFallbackBackend::free_pinned_host(void* ptr) {
    if (!ptr) return;
    free(ptr);
}

void* CPUFallbackBackend::allocate_device_memory(size_t bytes) {
    // In CPU Fallback, device memory is mapped to cache-aligned host RAM
    return allocate_pinned_host(bytes);
}

void CPUFallbackBackend::free_device_memory(void* ptr) {
    free_pinned_host(ptr);
}

bool CPUFallbackBackend::copy_host_to_device_async(void* dst_device, const void* src_host, size_t bytes, void* /*stream*/) {
    if (!dst_device || !src_host || bytes == 0) return false;
    std::memcpy(dst_device, src_host, bytes);
    return true;
}

bool CPUFallbackBackend::copy_device_to_host_async(void* dst_host, const void* src_device, size_t bytes, void* /*stream*/) {
    if (!dst_host || !src_device || bytes == 0) return false;
    std::memcpy(dst_host, src_device, bytes);
    return true;
}

void* CPUFallbackBackend::create_stream() {
    // Dummy stream handle for CPU fallback
    return (void*)0x1;
}

void CPUFallbackBackend::destroy_stream(void* /*stream*/) {
    // No-op for CPU
}

bool CPUFallbackBackend::synchronize_stream(void* /*stream*/) {
    return true;
}

bool CPUFallbackBackend::synchronize_device() {
    return true;
}

size_t CPUFallbackBackend::get_free_vram_bytes() {
    // Return available host RAM from /proc/meminfo
    std::ifstream meminfo("/proc/meminfo");
    std::string line;
    uint64_t mem_avail_kb = 0;
    while (std::getline(meminfo, line)) {
        if (line.rfind("MemAvailable:", 0) == 0) {
            std::sscanf(line.c_str(), "MemAvailable: %lu kB", &mem_avail_kb);
            break;
        }
    }
    return mem_avail_kb * 1024;
}

float CPUFallbackBackend::get_gpu_temperature_c() {
    // Read CPU temperature from thermal zone
    std::ifstream temp_file("/sys/class/thermal/thermal_zone0/temp");
    if (temp_file.is_open()) {
        int millidegrees = 0;
        if (temp_file >> millidegrees) {
            return millidegrees / 1000.0f;
        }
    }
    return 45.0f;
}

} // namespace samulibre::gpu
