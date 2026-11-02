#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Status: 0 = Clean, 1 = Infected/Malicious, 2 = Suspicious, 3 = Error
typedef enum {
    SAMULIBRE_GPU_STATUS_CLEAN = 0,
    SAMULIBRE_GPU_STATUS_INFECTED = 1,
    SAMULIBRE_GPU_STATUS_SUSPICIOUS = 2,
    SAMULIBRE_GPU_STATUS_ERROR = 3
} SamulibreGPUStatus;

// Profile: 0 = Silent, 1 = Balanced, 2 = Performance
typedef enum {
    SAMULIBRE_GPU_PROFILE_SILENT = 0,
    SAMULIBRE_GPU_PROFILE_BALANCED = 1,
    SAMULIBRE_GPU_PROFILE_PERFORMANCE = 2
} SamulibreGPUProfile;

// FFI-safe C Struct for Scan Result
typedef struct {
    int32_t status;                     // SamulibreGPUStatus
    char detection_name[256];           // Threat rule name or ML classification
    char engine_name[64];               // Backend used (e.g. "NVIDIA_CUDA_Native")
    double entropy;                     // Shannon Entropy (0.0 to 8.0)
    int32_t is_packed;                  // 1 if entropy >= 7.20 or UPX detected
    float ml_risk_probability;          // 0.0 to 1.0
    char ml_verdict[32];                // "CLEAN", "SUSPICIOUS", "MALICIOUS"
    uint64_t scan_time_ms;              // Duration in milliseconds
    int32_t quarantine_recommended;     // 1 if quarantined recommended by correlation
} SamulibreCScanResult;

// FFI-safe C Struct for Hardware Telemetry
typedef struct {
    float gpu_temperature_c;
    float gpu_power_watts;
    size_t vram_used_mb;
    size_t vram_total_mb;
    size_t ram_used_mb;
    float system_load_1min;
    int32_t is_throttled;
    int32_t is_gpu_accelerated;
    char telemetry_source[32];
} SamulibreCTelemetry;

// Opaque engine context handle
typedef void* SamulibreGPUContext;

// Lifecycle Management
SamulibreGPUContext samulibre_gpu_create(int32_t profile_mode);
void samulibre_gpu_destroy(SamulibreGPUContext ctx);

// Hardware Query
int32_t samulibre_gpu_is_accelerated(SamulibreGPUContext ctx);
const char* samulibre_gpu_get_backend_name(SamulibreGPUContext ctx);

// Scan Functions
int32_t samulibre_gpu_scan_file(SamulibreGPUContext ctx, const char* file_path, SamulibreCScanResult* out_result);
int32_t samulibre_gpu_scan_buffer(SamulibreGPUContext ctx, const uint8_t* data, size_t size, const char* virtual_name, SamulibreCScanResult* out_result);

// Control & Telemetry
void samulibre_gpu_request_cancel(SamulibreGPUContext ctx);
void samulibre_gpu_reset_cancel(SamulibreGPUContext ctx);
int32_t samulibre_gpu_get_telemetry(SamulibreGPUContext ctx, SamulibreCTelemetry* out_telemetry);

#ifdef __cplusplus
}
#endif
