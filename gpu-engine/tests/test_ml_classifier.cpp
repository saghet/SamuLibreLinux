#include "compute_engine.hpp"
#include "signature_scanner.hpp"
#include "elf_feature_extractor.hpp"
#include "ml_classifier.hpp"
#include <iostream>
#include <cassert>
#include <vector>
#include <cstring>
#include <iomanip>
#include <elf.h>

int main() {
    std::cout << "================================================================" << std::endl;
    std::cout << "  SAMULIBRE GPU ENGINE - TEST SUITE: ML CLASSIFIER & ELF ONNX   " << std::endl;
    std::cout << "================================================================" << std::endl;

    samulibre::gpu::GPUComputeEngine engine(samulibre::gpu::ResourceProfile::PERFORMANCE);
    bool init_ok = engine.initialize();
    assert(init_ok);

    std::cout << "[1] Motor de cómputo inicializado." << std::endl;
    std::cout << "    - Backend activo: " << engine.get_active_backend_name() << std::endl;
    std::cout << "    - GPU Acelerada: " << (engine.is_gpu_accelerated() ? "SÍ" : "NO") << std::endl;

    samulibre::gpu::SignatureScanner scanner(engine);
    samulibre::gpu::MLClassifier classifier(engine, &scanner);

    // =========================================================================
    // Test 1: Feature Extraction on Clean Mock ELF Binary
    // =========================================================================
    std::cout << "\n[2] Verificando Extracción de Características Estáticas ELF..." << std::endl;

    // Crear cabecera ELF64 válida
    std::vector<uint8_t> clean_elf(4096, 0x00);
    Elf64_Ehdr ehdr;
    std::memset(&ehdr, 0, sizeof(ehdr));
    ehdr.e_ident[EI_MAG0] = ELFMAG0;
    ehdr.e_ident[EI_MAG1] = ELFMAG1;
    ehdr.e_ident[EI_MAG2] = ELFMAG2;
    ehdr.e_ident[EI_MAG3] = ELFMAG3;
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_type = ET_EXEC;
    ehdr.e_machine = EM_X86_64;
    ehdr.e_version = EV_CURRENT;
    ehdr.e_entry = 0x401000;
    ehdr.e_phoff = sizeof(Elf64_Ehdr);
    ehdr.e_phnum = 1;

    // Segmento normal RX (.text)
    Elf64_Phdr phdr;
    std::memset(&phdr, 0, sizeof(phdr));
    phdr.p_type = PT_LOAD;
    phdr.p_flags = PF_R | PF_X; // Read + Execute (Normal)
    phdr.p_offset = 0;
    phdr.p_vaddr = 0x400000;
    phdr.p_memsz = 0x2000;

    std::memcpy(clean_elf.data(), &ehdr, sizeof(ehdr));
    std::memcpy(clean_elf.data() + sizeof(ehdr), &phdr, sizeof(phdr));

    samulibre::gpu::ELFFeatureExtractor extractor(&scanner);
    auto clean_feats = extractor.extract_features(clean_elf.data(), clean_elf.size(), "clean_sample");

    assert(clean_feats.is_valid_elf);
    assert(clean_feats.elf_class == ELFCLASS64);
    assert(!clean_feats.has_rwx_section);
    assert(!clean_feats.has_suspicious_section_name);
    std::cout << "    - Archivo ELF64 detectado correctamente." << std::endl;
    std::cout << "    - Sección RWX: " << (clean_feats.has_rwx_section ? "SÍ" : "NO") << std::endl;
    std::cout << "    - Nombres sospechosos: " << (clean_feats.has_suspicious_section_name ? "SÍ" : "NO") << std::endl;

    auto clean_vec = extractor.vectorize(clean_feats, clean_elf.size());
    assert(clean_vec.values.size() == 32);
    std::cout << "    ✓ Vectorización de 32 dimensiones generada: PASADO 100%." << std::endl;

    // =========================================================================
    // Test 2: Classification of Clean Sample
    // =========================================================================
    std::cout << "\n[3] Clasificación de Muestra Limpia..." << std::endl;
    auto clean_res = classifier.classify_buffer(clean_elf.data(), clean_elf.size(), "clean_binary.elf", 101);

    std::cout << "    - Probabilidad de riesgo: " << std::fixed << std::setprecision(4) << clean_res.risk_probability << std::endl;
    std::cout << "    - Clasificación: " << clean_res.classification_label << std::endl;
    std::cout << "    - Proveedor de ejecución: " << clean_res.execution_provider << std::endl;
    std::cout << "    - Tiempo de inferencia: " << clean_res.inference_duration_ms << " ms" << std::endl;
    std::cout << "    - Atribuciones explicables: " << clean_res.contributing_features[0] << std::endl;

    assert(clean_res.risk_probability < 0.40f);
    assert(clean_res.classification_label == "CLEAN");
    assert(!clean_res.quarantine_recommended);
    std::cout << "    ✓ Clasificación de binario limpio: PASADO 100% (Riesgo bajo esperado)." << std::endl;

    // =========================================================================
    // Test 3: Classification of Highly Suspicious / Packed Malware Sample
    // =========================================================================
    std::cout << "\n[4] Clasificación de Muestra Maliciosa (UPX Packed + RWX + Anti-Debug)..." << std::endl;

    std::vector<uint8_t> mal_elf = clean_elf;
    // 1. Modificar segmento a W+X (Writable + Executable)
    Elf64_Phdr bad_phdr = phdr;
    bad_phdr.p_flags = PF_R | PF_W | PF_X; // RWX
    std::memcpy(mal_elf.data() + sizeof(ehdr), &bad_phdr, sizeof(bad_phdr));

    // 2. Inyectar cadenas sospechosas de packers, evasión y reverse shell
    std::string mal_markers = "UPX0 UPX! memfd_create ptrace /bin/bash /dev/tcp/192.168.1.100/4444";
    std::memcpy(mal_elf.data() + 1024, mal_markers.data(), mal_markers.size());

    // 3. Rellenar final con entropía alta
    for (size_t i = 2048; i < mal_elf.size(); ++i) {
        mal_elf[i] = static_cast<uint8_t>((i * 73 + 19) % 256);
    }

    auto mal_res = classifier.classify_buffer(mal_elf.data(), mal_elf.size(), "trojan_packed.elf", 102);

    std::cout << "    - Probabilidad de riesgo: " << std::fixed << std::setprecision(4) << mal_res.risk_probability << std::endl;
    std::cout << "    - Clasificación: " << mal_res.classification_label << std::endl;
    std::cout << "    - Proveedor de ejecución: " << mal_res.execution_provider << std::endl;
    std::cout << "    - Tiempo de inferencia: " << mal_res.inference_duration_ms << " ms" << std::endl;
    std::cout << "    - Características de riesgo identificadas:" << std::endl;
    for (const auto& feat : mal_res.contributing_features) {
        std::cout << "        • " << feat << std::endl;
    }

    assert(mal_res.risk_probability >= 0.85f);
    assert(mal_res.classification_label == "MALICIOUS");
    std::cout << "    ✓ Clasificación de malware: PASADO 100% (Clasificado MALICIOUS con probabilidad alta)." << std::endl;

    // =========================================================================
    // Test 4: Parity between GPU Inactive (CPU Fallback) and GPU
    // =========================================================================
    std::cout << "\n[5] Verificando Paridad de Inferencia GPU vs CPU Fallback..." << std::endl;

    engine.force_fallback_to_cpu("Simulación para auditoría de paridad ML");
    samulibre::gpu::MLClassifier cpu_classifier(engine, &scanner);
    auto cpu_res = cpu_classifier.classify_buffer(mal_elf.data(), mal_elf.size(), "trojan_cpu_check.elf", 103);

    std::cout << "    - Probabilidad CPU Fallback: " << cpu_res.risk_probability << std::endl;
    std::cout << "    - Clasificación CPU Fallback: " << cpu_res.classification_label << std::endl;
    std::cout << "    - Proveedor: " << cpu_res.execution_provider << std::endl;

    assert(cpu_res.classification_label == "MALICIOUS");
    std::cout << "    ✓ Paridad funcional GPU <-> CPU Fallback: PASADO 100%." << std::endl;

    // =========================================================================
    // Test 5: Real Host System Binary Classification (/bin/sh)
    // =========================================================================
    std::cout << "\n[6] Clasificando Binario Real del Sistema Operativo (/bin/sh)..." << std::endl;

    samulibre::gpu::GPUComputeEngine live_engine;
    live_engine.initialize();
    samulibre::gpu::MLClassifier live_classifier(live_engine, &scanner);

    auto real_res = live_classifier.classify_file("/bin/sh", 200);

    std::cout << "    - Archivo evaluado: " << real_res.file_path << std::endl;
    std::cout << "    - Probabilidad estimada: " << real_res.risk_probability << std::endl;
    std::cout << "    - Veredicto ML: " << real_res.classification_label << std::endl;
    std::cout << "    - Cuarentena recomendada: " << (real_res.quarantine_recommended ? "SÍ" : "NO") << std::endl;

    assert(real_res.classification_label != "MALICIOUS");
    std::cout << "    ✓ Binario del sistema protegido y validado sin falsos positivos." << std::endl;

    std::cout << "\n================================================================" << std::endl;
    std::cout << "  TODAS LAS PRUEBAS DE LA FASE 5 COMPLETADAS CON ÉXITO (100% PASS)" << std::endl;
    std::cout << "================================================================" << std::endl;

    return 0;
}
