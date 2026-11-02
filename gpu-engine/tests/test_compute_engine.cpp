#include "compute_engine.hpp"
#include <iostream>
#include <vector>
#include <cstring>
#include <cassert>

using namespace samulibre::gpu;

int main() {
    std::cout << "=== [TEST] GPU Compute Engine & Memory Transfers ===" << std::endl;

    GPUComputeEngine engine(ResourceProfile::BALANCED);
    bool init_ok = engine.initialize();
    assert(init_ok && "GPUComputeEngine debe inicializar correctamente");

    std::cout << "Backend Activo: " << engine.get_active_backend_name() << std::endl;
    std::cout << "¿Acelerado por GPU?: " << (engine.is_gpu_accelerated() ? "SÍ" : "NO (CPU Fallback)") << std::endl;

    // Test 1: Pinned Host Memory Allocation & Zero-Copy Integrity
    const size_t test_size = 4 * 1024 * 1024; // 4 MB chunk
    void* host_src = engine.allocate_host_buffer(test_size);
    void* host_dst = engine.allocate_host_buffer(test_size);
    void* dev_buf = engine.allocate_device_buffer(test_size);

    assert(host_src != nullptr && "Fallo al alojar memoria fijada de entrada");
    assert(host_dst != nullptr && "Fallo al alojar memoria fijada de salida");
    assert(dev_buf != nullptr && "Fallo al alojar buffer en dispositivo/VRAM");

    // Llenar buffer con patrón conocido (EICAR signature prefix + incremental bytes)
    const char* sample_pattern = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    size_t pattern_len = std::strlen(sample_pattern);

    uint8_t* u8_src = static_cast<uint8_t*>(host_src);
    for (size_t i = 0; i < test_size; ++i) {
        u8_src[i] = sample_pattern[i % pattern_len] ^ (uint8_t)(i & 0xFF);
    }
    std::memset(host_dst, 0, test_size);

    // Test 2: Host to Device Transfer (PCIe Bus)
    bool h2d_ok = engine.transfer_to_device(dev_buf, host_src, test_size);
    assert(h2d_ok && "Fallo en transferencia PCIe Host-to-Device");

    // Test 3: Device to Host Transfer (PCIe Bus)
    bool d2h_ok = engine.transfer_to_host(host_dst, dev_buf, test_size);
    assert(d2h_ok && "Fallo en transferencia PCIe Device-to-Host");

    engine.synchronize();

    // Test 4: Bitwise Integrity Check
    int diff = std::memcmp(host_src, host_dst, test_size);
    assert(diff == 0 && "Corrupción de datos detectada en la transferencia de VRAM");
    std::cout << "✓ Integridad de transferencia PCIe de 4 MB validada (100% idéntico bit a bit)" << std::endl;

    // Liberar recursos activos en CUDA antes de la conmutación
    engine.free_device_buffer(dev_buf);
    engine.free_host_buffer(host_src);
    engine.free_host_buffer(host_dst);

    // Test 5: Fallback Resilience Simulation
    std::cout << "Probando conmutación dinámica de fallback..." << std::endl;
    engine.force_fallback_to_cpu("Simulación de fallo de VRAM");
    assert(!engine.is_gpu_accelerated() && "El motor debe estar en modo CPU Fallback");

    void* fallback_dev = engine.allocate_device_buffer(1024);
    assert(fallback_dev != nullptr && "CPU Fallback debe continuar asignando memoria sin excepción");
    engine.free_device_buffer(fallback_dev);

    engine.shutdown();

    std::cout << ">>> [TEST PASSED] GPU Compute Engine verificado con éxito." << std::endl;
    return 0;
}
