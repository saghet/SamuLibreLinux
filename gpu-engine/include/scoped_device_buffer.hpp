#pragma once

#include "compute_engine.hpp"
#include <cstddef>
#include <utility>

namespace samulibre::gpu {

// RAII Wrapper for Device GPU allocations (ARCH-01)
class ScopedDeviceBuffer {
public:
    ScopedDeviceBuffer(GPUComputeEngine& engine, size_t bytes)
        : engine_(engine), size_(bytes), ptr_(nullptr) {
        if (bytes > 0) {
            ptr_ = engine_.allocate_device_buffer(bytes);
        }
    }

    ~ScopedDeviceBuffer() {
        reset();
    }

    // Disable copy to prevent double-free
    ScopedDeviceBuffer(const ScopedDeviceBuffer&) = delete;
    ScopedDeviceBuffer& operator=(const ScopedDeviceBuffer&) = delete;

    // Enable move semantics
    ScopedDeviceBuffer(ScopedDeviceBuffer&& other) noexcept
        : engine_(other.engine_), size_(other.size_), ptr_(other.ptr_) {
        other.ptr_ = nullptr;
        other.size_ = 0;
    }

    ScopedDeviceBuffer& operator=(ScopedDeviceBuffer&& other) noexcept {
        if (this != &other) {
            reset();
            ptr_ = other.ptr_;
            size_ = other.size_;
            other.ptr_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    void* get() const noexcept { return ptr_; }
    size_t size() const noexcept { return size_; }
    bool valid() const noexcept { return ptr_ != nullptr; }

    void reset(size_t new_bytes = 0) {
        if (ptr_) {
            engine_.free_device_buffer(ptr_);
            ptr_ = nullptr;
            size_ = 0;
        }
        if (new_bytes > 0) {
            ptr_ = engine_.allocate_device_buffer(new_bytes);
            size_ = ptr_ ? new_bytes : 0;
        }
    }

private:
    GPUComputeEngine& engine_;
    size_t size_ = 0;
    void* ptr_ = nullptr;
};

} // namespace samulibre::gpu
