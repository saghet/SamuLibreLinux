#pragma once

#include "ml_types.hpp"
#include "elf_feature_extractor.hpp"
#include "compute_engine.hpp"
#include "signature_scanner.hpp"
#include "scoped_device_buffer.hpp"
#include <memory>
#include <mutex>

namespace samulibre::gpu {

class MLClassifier {
public:
    explicit MLClassifier(GPUComputeEngine& engine,
                          SignatureScanner* scanner = nullptr,
                          const MLClassifierConfig& config = MLClassifierConfig{});
    ~MLClassifier();

    bool initialize();
    void set_thresholds(float suspicious, float malicious);

    // Classification entry points
    MLInferenceResult classify_buffer(const uint8_t* data, size_t size,
                                      const std::string& filename = "in_memory_sample",
                                      uint64_t task_id = 1);

    MLInferenceResult classify_file(const std::string& file_path, uint64_t task_id = 1);

    // Batch classification for high-throughput directory scanning
    std::vector<MLInferenceResult> classify_batch(const std::vector<std::vector<uint8_t>>& buffers,
                                                 const std::vector<std::string>& filenames);

    const MLClassifierConfig& get_config() const { return config_; }

private:
    float run_inference_gpu(const float* features, size_t batch_size);
    float run_inference_cpu(const float* features);

    void extract_attributions(const MLFeatureVector& vec, float risk_score,
                              std::vector<std::string>& contributing_features);

    bool init_gpu_ml_kernels();

    GPUComputeEngine& engine_;
    SignatureScanner* scanner_;
    ELFFeatureExtractor feature_extractor_;
    MLClassifierConfig config_;

    std::mutex classifier_mutex_;
    bool initialized_ = false;

    // GPU ML resources (PTX modules & functions when CUDA is active)
    void* cuda_module_ = nullptr;
    void* ml_kernel_fn_ = nullptr;
    bool gpu_ml_ready_ = false;

    // Persistent GPU scratch memory arena (PERF-02 & ARCH-01)
    std::unique_ptr<ScopedDeviceBuffer> persistent_d_feats_;
    std::unique_ptr<ScopedDeviceBuffer> persistent_d_scores_;
    size_t persistent_batch_capacity_ = 0;

    // Embedded Pre-Trained Weights (Multilayer Perceptron 32 -> 64 -> 32 -> 1)
    // Modeled on static Linux malware analysis datasets (VirusShare Linux ELF / DikeDataset)
    std::vector<float> w1_; // 32 * 64 = 2048
    std::vector<float> b1_; // 64
    std::vector<float> w2_; // 64 * 32 = 2048
    std::vector<float> b2_; // 32
    std::vector<float> w3_; // 32 * 1 = 32
    float b3_ = 0.0f;

    void init_embedded_weights();
};

} // namespace samulibre::gpu
