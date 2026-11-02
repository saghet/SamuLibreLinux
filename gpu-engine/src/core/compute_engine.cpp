#include "compute_engine.hpp"
#include "cuda_backend.hpp"
#include "cpu_fallback.hpp"
#include <iostream>

namespace samulibre::gpu {

GPUComputeEngine::GPUComputeEngine(ResourceProfile profile)
    : profile_(profile) {
}

GPUComputeEngine::~GPUComputeEngine() {
    shutdown();
}

bool GPUComputeEngine::initialize() {
    if (is_initialized_) return true;

    active_device_ = detector_.select_best_device(profile_);

    std::cout << "[GPUComputeEngine] Dispositivo seleccionado: " << active_device_.name 
              << " (Backend: " << (active_device_.backend == BackendType::CUDA ? "CUDA" : 
                                   (active_device_.backend == BackendType::OPENCL ? "OpenCL" : "CPU Fallback")) 
              << ", VRAM: " << (active_device_.total_vram_bytes / (1024 * 1024)) << " MB)" << std::endl;

    if (active_device_.backend == BackendType::CUDA) {
        auto cuda_backend = std::make_unique<CUDABackend>();
        if (cuda_backend->initialize(active_device_)) {
            backend_ = std::move(cuda_backend);
            is_initialized_ = true;
            fallback_triggered_ = false;
            std::cout << "[GPUComputeEngine] Backend CUDA inicializado exitosamente." << std::endl;
            return true;
        } else {
            std::cerr << "[GPUComputeEngine] Advertencia: Falló inicialización de CUDA. Conmutando a CPU Fallback..." << std::endl;
        }
    }

    // Default or Fallback to CPU
    auto cpu_backend = std::make_unique<CPUFallbackBackend>();
    cpu_backend->initialize(active_device_);
    backend_ = std::move(cpu_backend);
    is_initialized_ = true;
    fallback_triggered_ = true;
    std::cout << "[GPUComputeEngine] Backend CPU Fallback activo y operativo." << std::endl;

    return true;
}

void GPUComputeEngine::shutdown() {
    if (!is_initialized_) return;

    if (backend_) {
        backend_->shutdown();
        backend_.reset();
    }
    is_initialized_ = false;
}

bool GPUComputeEngine::is_gpu_accelerated() const {
    return is_initialized_ && backend_ && (backend_->get_backend_type() != BackendType::CPU_FALLBACK);
}

std::string GPUComputeEngine::get_active_backend_name() const {
    if (!backend_) return "None";
    return backend_->get_backend_name();
}

const GPUDeviceInfo& GPUComputeEngine::get_active_device_info() const {
    return active_device_;
}

void* GPUComputeEngine::allocate_host_buffer(size_t bytes) {
    if (!backend_) return nullptr;
    return backend_->allocate_pinned_host(bytes);
}

void GPUComputeEngine::free_host_buffer(void* ptr) {
    if (!backend_ || !ptr) return;
    backend_->free_pinned_host(ptr);
}

void* GPUComputeEngine::allocate_device_buffer(size_t bytes) {
    if (!backend_) return nullptr;
    void* ptr = backend_->allocate_device_memory(bytes);
    if (!ptr && is_gpu_accelerated()) {
        std::cerr << "[GPUComputeEngine] Out of VRAM on GPU. Disparando conmutación a CPU Fallback..." << std::endl;
        force_fallback_to_cpu("Out of VRAM error");
        return backend_->allocate_device_memory(bytes);
    }
    return ptr;
}

void GPUComputeEngine::free_device_buffer(void* ptr) {
    if (!backend_ || !ptr) return;
    backend_->free_device_memory(ptr);
}

bool GPUComputeEngine::transfer_to_device(void* dst_device, const void* src_host, size_t bytes, void* stream) {
    if (!backend_) return false;
    return backend_->copy_host_to_device_async(dst_device, src_host, bytes, stream);
}

bool GPUComputeEngine::transfer_to_host(void* dst_host, const void* src_device, size_t bytes, void* stream) {
    if (!backend_) return false;
    return backend_->copy_device_to_host_async(dst_host, src_device, bytes, stream);
}

bool GPUComputeEngine::synchronize() {
    if (!backend_) return false;
    return backend_->synchronize_device();
}

void GPUComputeEngine::force_fallback_to_cpu(const std::string& reason) {
    std::cout << "[GPUComputeEngine] Conmutando a CPU Fallback por: " << reason << std::endl;
    if (backend_) {
        backend_->shutdown();
    }
    auto cpu = std::make_unique<CPUFallbackBackend>();
    cpu->initialize(active_device_);
    backend_ = std::move(cpu);
    fallback_triggered_ = true;
}

} // namespace samulibre::gpu
