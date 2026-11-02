#include "resource_monitor.hpp"
#include "compute_engine.hpp"
#include "signature_scanner.hpp"
#include "ml_classifier.hpp"
#include "batch_scheduler.hpp"
#include <iostream>
#include <cassert>
#include <iomanip>
#include <chrono>

int main() {
    std::cout << "================================================================" << std::endl;
    std::cout << "  SAMULIBRE GPU ENGINE - TEST SUITE: RESOURCE MONITOR & CONTROL " << std::endl;
    std::cout << "================================================================" << std::endl;

    samulibre::gpu::ResourceMonitor monitor(samulibre::gpu::ResourceProfile::BALANCED);

    // =========================================================================
    // Test 1: Real-time Telemetry Acquisition
    // =========================================================================
    std::cout << "\n[1] Capturando Telemetría en Tiempo Real de GPU y Sistema..." << std::endl;
    auto snap = monitor.capture_snapshot();

    std::cout << "    - Fuente de telemetría: " << snap.telemetry_source << std::endl;
    std::cout << "    - Temperatura GPU: " << std::fixed << std::setprecision(1) << snap.gpu_temperature_c << " °C" << std::endl;
    std::cout << "    - Consumo energético GPU: " << snap.gpu_power_watts << " W" << std::endl;
    std::cout << "    - VRAM Utilizada: " << snap.vram_used_mb << " MB / " << snap.vram_total_mb << " MB (Libre: " << snap.vram_free_mb << " MB)" << std::endl;
    std::cout << "    - RAM del Host: " << snap.ram_used_mb << " MB / " << snap.ram_total_mb << " MB" << std::endl;
    std::cout << "    - Carga del sistema (1 min): " << snap.system_load_1min << std::endl;
    std::cout << "    - Hilos CPU disponibles: " << snap.cpu_core_count << std::endl;
    std::cout << "    - Estado de estrangulamiento (throttle): " << (snap.is_throttled ? "ACTIVO" : "NORMAL") << std::endl;
    std::cout << "    - Causa: " << snap.reason_description << std::endl;

    assert(snap.gpu_temperature_c > 20.0f && snap.gpu_temperature_c < 100.0f);
    assert(snap.vram_total_mb > 0);
    assert(snap.ram_total_mb > 0);
    assert(snap.cpu_core_count > 0);
    std::cout << "    ✓ Captura de telemetría de hardware: PASADO 100%." << std::endl;

    // =========================================================================
    // Test 2: Resource Profiles and Non-Percentage Configurable Limits
    // =========================================================================
    std::cout << "\n[2] Verificando Perfiles y Límites Configurables de Recursos..." << std::endl;

    // A. Silent Profile
    monitor.set_profile(samulibre::gpu::ResourceProfile::SILENT);
    auto t_silent = monitor.get_thresholds();
    std::cout << "    - Silent: VRAM máx = " << t_silent.max_vram_mb << " MB, Temp máx = " 
              << t_silent.max_gpu_temp_c << " °C, Delay = " << t_silent.throttle_delay_ms << " ms" << std::endl;
    assert(t_silent.max_vram_mb == 512);
    assert(t_silent.max_gpu_temp_c == 68.0f);

    // B. Balanced Profile
    monitor.set_profile(samulibre::gpu::ResourceProfile::BALANCED);
    auto t_bal = monitor.get_thresholds();
    std::cout << "    - Balanced: VRAM máx = " << t_bal.max_vram_mb << " MB, Temp máx = " 
              << t_bal.max_gpu_temp_c << " °C, Delay = " << t_bal.throttle_delay_ms << " ms" << std::endl;
    assert(t_bal.max_vram_mb == 2048);
    assert(t_bal.max_gpu_temp_c == 78.0f);

    // C. Performance Profile
    monitor.set_profile(samulibre::gpu::ResourceProfile::PERFORMANCE);
    auto t_perf = monitor.get_thresholds();
    std::cout << "    - Performance: VRAM máx = " << t_perf.max_vram_mb << " MB, Temp máx = " 
              << t_perf.max_gpu_temp_c << " °C, Delay = " << t_perf.throttle_delay_ms << " ms" << std::endl;
    assert(t_perf.max_vram_mb == 6144);
    assert(t_perf.max_gpu_temp_c == 84.0f);

    // D. Custom Non-Percentage Explicit Limits
    samulibre::gpu::ResourceThresholds custom;
    custom.max_vram_mb = 3500; // Exact MB, not arbitrary percentage
    custom.max_gpu_temp_c = 72.5f;
    custom.max_gpu_power_watts = 45.0f;
    monitor.set_thresholds(custom);
    assert(monitor.get_thresholds().max_vram_mb == 3500);
    assert(monitor.get_thresholds().max_gpu_temp_c == 72.5f);
    std::cout << "    ✓ Perfiles y límites explícitos configurables: PASADO 100%." << std::endl;

    // =========================================================================
    // Test 3: Dynamic Throttling Simulation
    // =========================================================================
    std::cout << "\n[3] Verificando Simulación de Estrangulamiento Adaptativo..." << std::endl;

    // Forzar umbral de temperatura por debajo de la actual para probar activación
    samulibre::gpu::ResourceThresholds low_thresh = monitor.get_thresholds();
    low_thresh.max_gpu_temp_c = 30.0f; // La GPU está a ~51 °C
    low_thresh.throttle_delay_ms = 10;
    monitor.set_thresholds(low_thresh);

    auto throttled_snap = monitor.capture_snapshot();
    std::cout << "    - Condición de temperatura (" << throttled_snap.gpu_temperature_c << " °C >= " 
              << low_thresh.max_gpu_temp_c << " °C) -> Throttling: " 
              << (throttled_snap.is_throttled ? "ACTIVADO" : "INACTIVO") << std::endl;
    assert(throttled_snap.is_throttled);
    assert(throttled_snap.reason == samulibre::gpu::ThrottleReason::TEMPERATURE_HIGH);

    auto start_t = std::chrono::high_resolution_clock::now();
    bool throttled_ok = monitor.evaluate_and_throttle();
    auto end_t = std::chrono::high_resolution_clock::now();
    double delay_elapsed = std::chrono::duration<double, std::milli>(end_t - start_t).count();

    assert(throttled_ok);
    assert(delay_elapsed >= 8.0); // Verificó sleep adaptativo
    std::cout << "    - Pausa adaptativa ejecutada: " << delay_elapsed << " ms" << std::endl;
    std::cout << "    ✓ Control de sobrecarga y estrangulamiento térmico: PASADO 100%." << std::endl;

    // Restaurar umbral equilibrado
    monitor.set_profile(samulibre::gpu::ResourceProfile::BALANCED);

    // =========================================================================
    // Test 4: Cooperative Task Cancellation (Zero Deadlocks)
    // =========================================================================
    std::cout << "\n[4] Verificando Cancelación Cooperativa de Tareas (Zero Deadlocks)..." << std::endl;

    samulibre::gpu::GPUComputeEngine engine(samulibre::gpu::ResourceProfile::BALANCED);
    engine.initialize();
    samulibre::gpu::SignatureScanner scanner(engine);
    samulibre::gpu::MLClassifier classifier(engine, &scanner);
    samulibre::gpu::BatchScheduler scheduler(engine, scanner, classifier);

    // Encolar 15 tareas pesadas
    for (int i = 0; i < 15; ++i) {
        std::vector<uint8_t> data(1024 * 1024, 0x44); // 1 MB cada una
        scheduler.enqueue_buffer(data.data(), data.size(), "task_" + std::to_string(i));
    }
    assert(scheduler.pending_tasks_count() == 15);

    // Solicitar cancelación inmediata antes de ejecutar
    scheduler.get_resource_monitor().request_cancellation();
    assert(scheduler.get_resource_monitor().is_cancellation_requested());

    auto cancel_start = std::chrono::high_resolution_clock::now();
    auto cancel_metrics = scheduler.process_all();
    auto cancel_end = std::chrono::high_resolution_clock::now();
    double cancel_ms = std::chrono::duration<double, std::milli>(cancel_end - cancel_start).count();

    std::cout << "    - Tiempo de interrupción segura: " << cancel_ms << " ms" << std::endl;
    std::cout << "    - Tareas ejecutadas antes de corte seguro: " << cancel_metrics.total_tasks << std::endl;
    assert(cancel_metrics.total_tasks == 0); // No procesó nada tras la cancelación
    assert(cancel_ms < 50.0); // Respuesta casi instantánea sin deadlocks
    std::cout << "    ✓ Cancelación cooperativa segura sin bloqueos: PASADO 100%." << std::endl;

    std::cout << "\n================================================================" << std::endl;
    std::cout << "  TODAS LAS PRUEBAS DE LA FASE 7 COMPLETADAS CON ÉXITO (100% PASS)" << std::endl;
    std::cout << "================================================================" << std::endl;

    return 0;
}
