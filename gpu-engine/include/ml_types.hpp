#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace samulibre::gpu {

enum class MLRiskClass {
    CLEAN = 0,
    SUSPICIOUS = 1,
    MALICIOUS = 2
};

struct ELFFeatures {
    bool is_valid_elf = false;
    uint8_t elf_class = 0; // 1 = 32-bit, 2 = 64-bit
    uint16_t machine = 0; // EM_386, EM_X86_64, EM_AARCH64, etc.
    uint64_t entry_point = 0;
    uint16_t section_count = 0;
    uint16_t program_header_count = 0;
    
    // Anomaly flags
    bool has_rwx_section = false;           // Write + Execute section (injection/unpacking)
    bool has_suspicious_section_name = false; // UPX, packed, etc.
    bool entry_point_outside_text = false;
    bool is_stripped = false;
    bool missing_section_headers = false;
    
    // Entropy metrics
    double overall_entropy = 0.0;
    double text_section_entropy = 0.0;
    double data_section_entropy = 0.0;
    
    // Suspicious API indicators
    bool uses_ptrace = false;               // Anti-debugging
    bool uses_execve = false;               // Shell execution
    bool uses_sockets = false;              // Network comms
    bool uses_crypto = false;               // Crypto/Ransomware
    bool manipulates_permissions = false;   // chmod, setuid
    bool uses_memfd = false;                // Fileless execution (memfd_create)
    
    // String features
    uint32_t suspicious_strings_count = 0;
    uint32_t ip_url_count = 0;
    uint32_t base64_strings_count = 0;
};

// 32-dimensional normalized feature vector for ML Model
struct MLFeatureVector {
    static constexpr size_t DIMENSION = 32;
    std::vector<float> values; // Exactly 32 floats in range [0.0, 1.0]
    std::vector<std::string> feature_names;

    MLFeatureVector() : values(DIMENSION, 0.0f) {
        feature_names = {
            "overall_entropy_norm",
            "has_rwx_section",
            "suspicious_section_name",
            "entry_point_anomaly",
            "section_count_norm",
            "is_stripped",
            "missing_sections",
            "text_entropy_norm",
            "data_entropy_norm",
            "anti_debug_ptrace",
            "execve_shell_api",
            "network_socket_api",
            "crypto_encryption_api",
            "privilege_escalation_api",
            "fileless_memfd_api",
            "suspicious_strings_norm",
            "network_endpoints_norm",
            "base64_density_norm",
            "file_size_log_norm",
            "imported_symbols_norm",
            "exported_symbols_norm",
            "relocation_entries_norm",
            "dynamic_linking_flag",
            "segment_alignment_anomaly",
            "zero_day_heuristic_entropy",
            "text_size_ratio",
            "data_size_ratio",
            "null_byte_ratio",
            "printable_ascii_ratio",
            "high_entropy_blocks_ratio",
            "header_padding_anomaly",
            "packer_signature_weight"
        };
    }
};

struct MLInferenceResult {
    uint64_t task_id = 0;
    std::string file_path;
    float risk_probability = 0.0f; // 0.0 (clean) to 1.0 (malicious)
    MLRiskClass risk_class = MLRiskClass::CLEAN;
    std::string classification_label; // "CLEAN", "SUSPICIOUS", "MALICIOUS"
    std::vector<std::string> contributing_features; // Explainability / Feature Attribution
    std::string model_version = "SamuLibre-ELF-ONNX-v1.4";
    double inference_duration_ms = 0.0;
    std::string execution_provider; // "NVIDIA_CUDA_Native_ML" or "CPU_AVX2_Fallback_ML"
    bool quarantine_recommended = false; // Strictly requires correlation with other engines
};

struct MLClassifierConfig {
    float suspicious_threshold = 0.65f;
    float malicious_threshold = 0.85f;
    bool enable_gpu_acceleration = true;
    std::string model_path = "models/samulibre_elf_v1.onnx";
};

} // namespace samulibre::gpu
