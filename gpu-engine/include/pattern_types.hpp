#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace samulibre::gpu {

struct PatternRule {
    uint32_t id = 0;
    std::string name;
    std::string category; // e.g. "EICAR", "Ransomware_Tripwire", "Shellcode", "Credential_Dump"
    std::vector<uint8_t> bytes;
};

struct PatternMatch {
    uint32_t rule_id = 0;
    uint64_t offset = 0;
    std::string rule_name;
    std::string category;
};

struct BatchScanResult {
    uint64_t total_bytes_scanned = 0;
    double scan_duration_ms = 0.0;
    double throughput_mb_s = 0.0;
    double entropy_shannon = 0.0;
    bool is_suspicious_packed = false;
    std::vector<PatternMatch> matches;
    std::string backend_used;
};

} // namespace samulibre::gpu
