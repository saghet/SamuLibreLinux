#include "gpu_detector.hpp"
#include <iostream>
#include <cassert>

using namespace samulibre::gpu;

int main() {
    std::cout << "=== [TEST] GPU Detection Manager ===" << std::endl;

    GPUDetector detector;

    std::cout << "Driver CUDA disponible: " << (detector.has_cuda_driver() ? "SÍ" : "NO") << std::endl;
    std::cout << "Driver OpenCL disponible: " << (detector.has_opencl_driver() ? "SÍ" : "NO") << std::endl;
    std::cout << "Driver Vulkan disponible: " << (detector.has_vulkan_driver() ? "SÍ" : "NO") << std::endl;

    auto devices = detector.enumerate_devices();
    std::cout << "Dispositivos de cómputo detectados: " << devices.size() << std::endl;

    assert(!devices.empty() && "Debe haber al menos un dispositivo (CPU Fallback garantizado)");

    for (size_t i = 0; i < devices.size(); ++i) {
        const auto& dev = devices[i];
        std::cout << " [" << i << "] Nombre: " << dev.name
                  << " | Backend: " << (dev.backend == BackendType::CUDA ? "CUDA" : 
                                       (dev.backend == BackendType::OPENCL ? "OpenCL" : "CPU_FALLBACK"))
                  << " | VRAM: " << (dev.total_vram_bytes / (1024 * 1024)) << " MB"
                  << " | Compute Units: " << dev.compute_units
                  << " | Dedicated: " << (dev.is_dedicated ? "YES" : "NO")
                  << " | Pinned RAM: " << (dev.supports_pinned_memory ? "YES" : "NO")
                  << std::endl;

        assert(!dev.name.empty());
        assert(dev.total_vram_bytes > 0);
        assert(dev.compute_units > 0);
    }

    GPUDeviceInfo best = detector.select_best_device(ResourceProfile::BALANCED);
    std::cout << "Dispositivo Óptimo Seleccionado: " << best.name 
              << " (" << (best.backend == BackendType::CUDA ? "CUDA" : "CPU Fallback") << ")" << std::endl;

    assert(!best.name.empty());

    std::cout << ">>> [TEST PASSED] GPU Detection Manager verificado exitosamente." << std::endl;
    return 0;
}
