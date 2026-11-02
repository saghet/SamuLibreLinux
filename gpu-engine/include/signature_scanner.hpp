#pragma once

#include "pattern_types.hpp"
#include "compute_engine.hpp"
#include "scoped_device_buffer.hpp"
#include <vector>
#include <memory>
#include <mutex>

namespace samulibre::gpu {

class SignatureScanner {
public:
    explicit SignatureScanner(GPUComputeEngine& engine);
    ~SignatureScanner();

    // Rule management
    void add_rule(uint32_t id, const std::string& name, const std::string& category, const std::vector<uint8_t>& pattern);
    void load_default_malware_rules();
    size_t rule_count() const;
    void clear_rules();

    // Main scanning entrypoint
    BatchScanResult scan_buffer(const uint8_t* data, size_t size, int file_id = 0);

    // Parallel Shannon Entropy (0.0 to 8.0 bits/byte)
    double calculate_entropy(const uint8_t* data, size_t size);

private:
    BatchScanResult scan_gpu_cuda(const uint8_t* data, size_t size, int file_id);
    BatchScanResult scan_cpu_fallback(const uint8_t* data, size_t size, int file_id);

    double calculate_entropy_cpu(const uint8_t* data, size_t size);
    double calculate_entropy_gpu(const uint8_t* data, size_t size);

    GPUComputeEngine& engine_;
    std::vector<PatternRule> rules_;
    mutable std::mutex rules_mutex_;

    // GPU kernel resources (PTX modules & functions when CUDA is active)
    void* cuda_module_ = nullptr;
    void* pattern_kernel_fn_ = nullptr;
    void* entropy_kernel_fn_ = nullptr;
    bool gpu_kernels_loaded_ = false;

    bool init_gpu_kernels();
};

} // namespace samulibre::gpu
