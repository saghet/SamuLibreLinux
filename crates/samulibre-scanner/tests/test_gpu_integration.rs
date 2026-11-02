use samulibre_scanner::MultiEngineScanner;
use samulibre_types::FileScanStatus;
use std::fs;

#[test]
fn test_gpu_acceleration_integration() {
    println!("=== TEST: Integración GPU Engine con Rust MultiEngineScanner ===");

    let scanner = MultiEngineScanner::new();

    println!("    - GPU Engine Option: {}", if scanner.gpu_engine.is_some() { "Some" } else { "None" });

    // 1. Verificación de carga y aceleración
    let is_gpu = scanner.has_gpu_acceleration();
    println!("    - GPU Acelerada: {}", if is_gpu { "SÍ" } else { "NO" });
    assert!(is_gpu, "El motor GPU debe estar acelerado en hardware con driver CUDA/NVIDIA");

    let backend = scanner.get_gpu_backend_name().unwrap_or_default();
    println!("    - Backend reportado: {}", backend);
    assert_eq!(backend, "NVIDIA_CUDA_Native");

    // 2. Verificación de Telemetría
    if let Some(telemetry) = scanner.get_gpu_telemetry() {
        println!("    - Telemetría NVML:");
        println!("        • Temperatura GPU: {:.1} °C", telemetry.gpu_temperature_c);
        println!("        • Consumo Energético: {:.2} W", telemetry.gpu_power_watts);
        println!("        • VRAM: {} MB / {} MB", telemetry.vram_used_mb, telemetry.vram_total_mb);
        println!("        • Carga Sistema: {:.2}", telemetry.system_load_1min);
        assert!(telemetry.gpu_temperature_c > 20.0 && telemetry.gpu_temperature_c < 95.0);
        assert!(telemetry.vram_total_mb > 0);
    } else {
        panic!("Debe obtenerse telemetría del subsistema GPU");
    }

    // 3. Escaneo de Archivo con Amenaza (EICAR)
    let temp_dir = std::env::temp_dir();
    let mal_file = temp_dir.join("test_gpu_eicar_threat.com");
    let eicar_content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\nPadding to reach 2048 bytes for GPU pipeline streaming threshold................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................";
    fs::write(&mal_file, eicar_content).expect("Fallo al escribir archivo de prueba");

    let scan_res = scanner.scan_file(&mal_file).expect("Fallo al escanear archivo con GPU");
    println!("    - Resultado de escaneo de amenaza:");
    println!("        • Estado: {:?}", scan_res.status);
    println!("        • Detección: {:?}", scan_res.detection_name);
    println!("        • Motor: {}", scan_res.engine);
    println!("        • SHA256 (Validado CPU): {}", scan_res.sha256);
    println!("        • Tiempo: {} ms", scan_res.scan_time_ms);

    assert_eq!(scan_res.status, FileScanStatus::Infected);
    assert!(scan_res.engine.contains("GPU Engine"));
    assert!(!scan_res.sha256.is_empty());

    let _ = fs::remove_file(&mal_file);

    // 4. Escaneo de Archivo Limpio
    let clean_file = temp_dir.join("test_gpu_clean_sample.txt");
    let clean_content = b"SamuLibre Linux Open Source Antivirus and EDR. Normal document text without any threats or exploits. Clean binary test data padding................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................";
    fs::write(&clean_file, clean_content).expect("Fallo al escribir archivo limpio");

    let clean_res = scanner.scan_file(&clean_file).expect("Fallo al escanear archivo limpio");
    println!("    - Resultado de escaneo limpio:");
    println!("        • Estado: {:?}", clean_res.status);
    println!("        • Detección: {:?}", clean_res.detection_name);

    assert_eq!(clean_res.status, FileScanStatus::Clean);

    let _ = fs::remove_file(&clean_file);

    println!(">>> [TEST PASSED] Integración Rust FFI con SamuLibre GPU Engine 100% exitosa.");
}
