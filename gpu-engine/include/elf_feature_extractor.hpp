#pragma once

#include "ml_types.hpp"
#include "signature_scanner.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace samulibre::gpu {

class ELFFeatureExtractor {
public:
    explicit ELFFeatureExtractor(SignatureScanner* scanner = nullptr);
    ~ELFFeatureExtractor() = default;

    // Extract structured ELF features from memory buffer
    ELFFeatures extract_features(const uint8_t* data, size_t size, const std::string& filename = "");

    // Convert raw extracted features into normalized 32-dimensional ML feature vector
    MLFeatureVector vectorize(const ELFFeatures& features, size_t file_size);

    // Convenience method: extract and vectorize in a single pass
    MLFeatureVector extract_and_vectorize(const uint8_t* data, size_t size, const std::string& filename = "") {
        ELFFeatures raw = extract_features(data, size, filename);
        return vectorize(raw, size);
    }

private:
    void parse_elf_headers(const uint8_t* data, size_t size, ELFFeatures& feat);
    void analyze_sections_and_segments(const uint8_t* data, size_t size, ELFFeatures& feat);
    void inspect_strings_and_symbols(const uint8_t* data, size_t size, ELFFeatures& feat);

    SignatureScanner* scanner_ = nullptr;
};

} // namespace samulibre::gpu
