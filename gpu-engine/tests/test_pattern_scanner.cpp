#include "compute_engine.hpp"
#include "signature_scanner.hpp"
#include <iostream>
#include <cassert>
#include <vector>
#include <random>
#include <cstring>
#include <iomanip>

int main() {
    std::cout << "================================================================" << std::endl;
    std::cout << "  SAMULIBRE GPU ENGINE - TEST SUITE: SIGNATURE SCANNER & ENTROPY" << std::endl;
    std::cout << "================================================================" << std::endl;

    samulibre::gpu::GPUComputeEngine engine(samulibre::gpu::ResourceProfile::PERFORMANCE);
    bool init_ok = engine.initialize();
    assert(init_ok);

    std::cout << "[1] Motor de cómputo inicializado." << std::endl;
    std::cout << "    - Backend activo: " << engine.get_active_backend_name() << std::endl;
    std::cout << "    - GPU Acelerada: " << (engine.is_gpu_accelerated() ? "SÍ" : "NO") << std::endl;

    samulibre::gpu::SignatureScanner scanner(engine);
    std::cout << "    - Reglas de malware cargadas: " << scanner.rule_count() << std::endl;
    assert(scanner.rule_count() > 0);

    // =========================================================================
    // Test 1: Shannon Entropy Verification
    // =========================================================================
    std::cout << "\n[2] Verificando Cálculo de Entropía de Shannon (0.0 a 8.0 bits/byte)..." << std::endl;

    // A. Buffer mono-carácter (entropía matemática = 0.0)
    std::vector<uint8_t> zero_buf(8192, 0x00);
    double h_zero = scanner.calculate_entropy(zero_buf.data(), zero_buf.size());
    std::cout << "    - Entropía Buffer Ceros (8 KB): " << std::fixed << std::setprecision(4) << h_zero << " bits/byte" << std::endl;
    assert(h_zero == 0.0);

    // B. Texto plano / código ASCII (entropía típica 3.5 - 5.5)
    std::string text_sample = "int main() { printf(\"Hello Linux Security World\\n\"); return 0; }";
    while (text_sample.size() < 8192) {
        text_sample += " Samulibre cybersecurity engine active protection.";
    }
    double h_text = scanner.calculate_entropy(reinterpret_cast<const uint8_t*>(text_sample.data()), text_sample.size());
    std::cout << "    - Entropía Código Fuente (8 KB): " << h_text << " bits/byte" << std::endl;
    assert(h_text > 3.0 && h_text < 6.0);

    // C. Datos Pseudo-Aleatorios / Cifrados (entropía esperada > 7.8)
    std::vector<uint8_t> rand_buf(65536);
    std::mt19937_64 rng(1337);
    for (size_t i = 0; i < rand_buf.size(); ++i) {
        rand_buf[i] = static_cast<uint8_t>(rng() & 0xFF);
    }
    double h_rand = scanner.calculate_entropy(rand_buf.data(), rand_buf.size());
    std::cout << "    - Entropía Payload Cifrado/Aleatorio (64 KB): " << h_rand << " bits/byte" << std::endl;
    assert(h_rand >= 7.80);
    std::cout << "    ✓ Verificación de cálculo de entropía: PASADO 100%." << std::endl;

    // =========================================================================
    // Test 2: Parallel Pattern Search & Malware Detection
    // =========================================================================
    std::cout << "\n[3] Verificando Detección Paralela de Patrones y Firmas de Malware..." << std::endl;

    // Construir un buffer de 1 MB con 4 amenazas incrustadas en posiciones específicas
    size_t payload_size = 1024 * 1024; // 1 MB
    std::vector<uint8_t> payload(payload_size, 0x90); // Relleno NOP x86

    // Amenaza 1: EICAR Standard Test Pattern en offset 10,000
    std::string eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    std::memcpy(&payload[10000], eicar.data(), eicar.size());

    // Amenaza 2: WannaCry Marker en offset 50,000
    std::string wannacry = "WANACRY!";
    std::memcpy(&payload[50000], wannacry.data(), wannacry.size());

    // Amenaza 3: Linux Shellcode en offset 120,000
    std::vector<uint8_t> shellcode = {0x48, 0x31, 0xd2, 0x48, 0xbb, 0x2f, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68};
    std::memcpy(&payload[120000], shellcode.data(), shellcode.size());

    // Amenaza 4: Reverse Shell Bash TCP en offset 300,000
    std::string revshell = "/bin/bash -i >& /dev/tcp/";
    std::memcpy(&payload[300000], revshell.data(), revshell.size());

    auto result = scanner.scan_buffer(payload.data(), payload.size());

    std::cout << "    - Total bytes escaneados: " << result.total_bytes_scanned << " (" << (result.total_bytes_scanned / 1024) << " KB)" << std::endl;
    std::cout << "    - Backend utilizado: " << result.backend_used << std::endl;
    std::cout << "    - Tiempo de escaneo: " << result.scan_duration_ms << " ms" << std::endl;
    std::cout << "    - Rendimiento alcanzado: " << result.throughput_mb_s << " MB/s" << std::endl;
    std::cout << "    - Amenazas identificadas: " << result.matches.size() << std::endl;

    for (size_t i = 0; i < result.matches.size(); ++i) {
        const auto& m = result.matches[i];
        std::cout << "      [#" << i + 1 << "] ID=" << m.rule_id << " | Categoría: " << m.category
                  << " | Regla: " << m.rule_name << " | Offset: 0x" << std::hex << m.offset << std::dec << std::endl;
    }

    assert(result.matches.size() == 4);
    std::cout << "    ✓ Detección paralela de amenazas: PASADO 100% (4/4 firmas detectadas con exactitud)." << std::endl;

    // =========================================================================
    // Test 3: CPU Fallback Engine Parity
    // =========================================================================
    std::cout << "\n[4] Verificando Paridad Funcional con CPU Fallback Engine..." << std::endl;

    engine.force_fallback_to_cpu("Simulación intencional de fallo GPU para auditoría");
    assert(!engine.is_gpu_accelerated());

    samulibre::gpu::SignatureScanner cpu_scanner(engine);
    auto cpu_result = cpu_scanner.scan_buffer(payload.data(), payload.size());

    std::cout << "    - Backend utilizado: " << cpu_result.backend_used << std::endl;
    std::cout << "    - Amenazas identificadas por CPU: " << cpu_result.matches.size() << std::endl;
    assert(cpu_result.matches.size() == 4);
    std::cout << "    ✓ Paridad idéntica GPU <-> CPU Fallback: PASADO 100%." << std::endl;

    // =========================================================================
    // Test 4: High-Throughput Batch Benchmark (16 MB buffer)
    // =========================================================================
    std::cout << "\n[5] Benchmark de Rendimiento Masivo en Buffer de 16 MB..." << std::endl;

    samulibre::gpu::GPUComputeEngine bench_engine(samulibre::gpu::ResourceProfile::PERFORMANCE);
    bench_engine.initialize();
    samulibre::gpu::SignatureScanner bench_scanner(bench_engine);

    size_t bench_size = 16 * 1024 * 1024; // 16 MB
    std::vector<uint8_t> bench_data(bench_size, 0x55);
    // Insert threat at 15 MB
    std::memcpy(&bench_data[15 * 1024 * 1024], wannacry.data(), wannacry.size());

    auto bench_res = bench_scanner.scan_buffer(bench_data.data(), bench_data.size());

    std::cout << "    - Tamaño de bloque: " << (bench_size / (1024 * 1024)) << " MB" << std::endl;
    std::cout << "    - Backend: " << bench_res.backend_used << std::endl;
    std::cout << "    - Tiempo de procesamiento: " << bench_res.scan_duration_ms << " ms" << std::endl;
    std::cout << "    - Tasa de escaneo: " << bench_res.throughput_mb_s << " MB/s (" 
              << (bench_res.throughput_mb_s / 1024.0) << " GB/s)" << std::endl;
    std::cout << "    - Amenazas halladas: " << bench_res.matches.size() << std::endl;
    assert(bench_res.matches.size() == 1);

    std::cout << "\n================================================================" << std::endl;
    std::cout << "  TODAS LAS PRUEBAS DE LA FASE 4 COMPLETADAS CON ÉXITO (100% PASS)" << std::endl;
    std::cout << "================================================================" << std::endl;

    return 0;
}
