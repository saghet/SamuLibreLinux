#include "signature_scanner.hpp"
#include <iostream>
#include <cstring>
#include <cmath>
#include <chrono>
#include <algorithm>

namespace samulibre::gpu {

namespace {

const char* SCANNER_PTX_CODE = R"(.version 7.0
.target sm_50
.address_size 64

.visible .entry compute_histogram(
    .param .u64 d_data,
    .param .u32 data_len,
    .param .u64 d_hist
)
{
    .reg .b32 %r_tid;
    .reg .b32 %r_ctaid;
    .reg .b32 %r_ntid;
    .reg .b32 %r_nctaid;
    .reg .b32 %r_stride;
    .reg .b32 %r_len;
    .reg .b32 %r_i;
    .reg .b32 %r_val_b32;
    .reg .u8  %r_byte;
    .reg .u64 %r_data_base;
    .reg .u64 %r_data_ptr;
    .reg .u64 %r_hist_base;
    .reg .u64 %r_hist_ptr;
    .reg .u64 %r_offset;
    .reg .pred %p_done;

    mov.u32 %r_ctaid, %ctaid.x;
    mov.u32 %r_ntid, %ntid.x;
    mov.u32 %r_tid, %tid.x;
    mul.lo.u32 %r_ctaid, %r_ctaid, %r_ntid;
    add.u32 %r_tid, %r_ctaid, %r_tid;

    mov.u32 %r_nctaid, %nctaid.x;
    mul.lo.u32 %r_stride, %r_nctaid, %r_ntid;

    ld.param.u32 %r_len, [data_len];
    ld.param.u64 %r_data_base, [d_data];
    ld.param.u64 %r_hist_base, [d_hist];

    mov.u32 %r_i, %r_tid;

HIST_LOOP:
    setp.ge.u32 %p_done, %r_i, %r_len;
    @%p_done bra HIST_EXIT;

    cvt.u64.u32 %r_offset, %r_i;
    add.u64 %r_data_ptr, %r_data_base, %r_offset;
    ld.global.u8 %r_byte, [%r_data_ptr];

    cvt.u32.u8 %r_val_b32, %r_byte;
    mul.wide.u32 %r_offset, %r_val_b32, 4;
    add.u64 %r_hist_ptr, %r_hist_base, %r_offset;

    atom.global.add.u32 %r_val_b32, [%r_hist_ptr], 1;

    add.u32 %r_i, %r_i, %r_stride;
    bra HIST_LOOP;

HIST_EXIT:
    ret;
}

.visible .entry scan_patterns(
    .param .u64 d_data,
    .param .u32 data_len,
    .param .u64 d_patterns,
    .param .u32 num_patterns,
    .param .u64 d_match_count,
    .param .u64 d_matches,
    .param .u32 max_matches
)
{
    .reg .b32 %r_tid;
    .reg .b32 %r_ctaid;
    .reg .b32 %r_ntid;
    .reg .b32 %r_nctaid;
    .reg .b32 %r_stride;
    .reg .b32 %r_len;
    .reg .b32 %r_npat;
    .reg .b32 %r_pos;
    .reg .b32 %r_p;
    .reg .b32 %r_k;
    .reg .b32 %r_plen;
    .reg .b32 %r_rule_id;
    .reg .b32 %r_max_m;
    .reg .b32 %r_cur_m;
    .reg .b32 %r_idx32;
    .reg .u8  %r_b1;
    .reg .u8  %r_b2;
    .reg .u32 %r_v1;
    .reg .u32 %r_v2;
    .reg .u64 %r_data_base;
    .reg .u64 %r_pat_base;
    .reg .u64 %r_count_base;
    .reg .u64 %r_match_base;
    .reg .u64 %r_pat_ptr;
    .reg .u64 %r_byte_ptr;
    .reg .u64 %r_off64;
    .reg .pred %p_pos_done;
    .reg .pred %p_p_done;
    .reg .pred %p_k_done;
    .reg .pred %p_len_fit;
    .reg .pred %p_diff;
    .reg .pred %p_has_slot;

    mov.u32 %r_ctaid, %ctaid.x;
    mov.u32 %r_ntid, %ntid.x;
    mov.u32 %r_tid, %tid.x;
    mul.lo.u32 %r_ctaid, %r_ctaid, %r_ntid;
    add.u32 %r_tid, %r_ctaid, %r_tid;

    mov.u32 %r_nctaid, %nctaid.x;
    mul.lo.u32 %r_stride, %r_nctaid, %r_ntid;

    ld.param.u32 %r_len, [data_len];
    ld.param.u32 %r_npat, [num_patterns];
    ld.param.u32 %r_max_m, [max_matches];
    ld.param.u64 %r_data_base, [d_data];
    ld.param.u64 %r_pat_base, [d_patterns];
    ld.param.u64 %r_count_base, [d_match_count];
    ld.param.u64 %r_match_base, [d_matches];

    mov.u32 %r_pos, %r_tid;

POS_LOOP:
    setp.ge.u32 %p_pos_done, %r_pos, %r_len;
    @%p_pos_done bra SCAN_EXIT;

    mov.u32 %r_p, 0;

PAT_LOOP:
    setp.ge.u32 %p_p_done, %r_p, %r_npat;
    @%p_p_done bra NEXT_POS;

    // Pattern struct size = 128 bytes: rule_id (offset 0), len (offset 4), bytes (offset 8)
    mul.wide.u32 %r_off64, %r_p, 128;
    add.u64 %r_pat_ptr, %r_pat_base, %r_off64;

    ld.global.u32 %r_plen, [%r_pat_ptr+4];

    add.u32 %r_idx32, %r_pos, %r_plen;
    setp.le.u32 %p_len_fit, %r_idx32, %r_len;
    @!%p_len_fit bra NEXT_PAT;

    mov.u32 %r_k, 0;

BYTE_LOOP:
    setp.ge.u32 %p_k_done, %r_k, %r_plen;
    @%p_k_done bra MATCH_FOUND;

    add.u32 %r_idx32, %r_pos, %r_k;
    cvt.u64.u32 %r_off64, %r_idx32;
    add.u64 %r_byte_ptr, %r_data_base, %r_off64;
    ld.global.u8 %r_b1, [%r_byte_ptr];

    cvt.u64.u32 %r_off64, %r_k;
    add.u64 %r_byte_ptr, %r_pat_ptr, %r_off64;
    ld.global.u8 %r_b2, [%r_byte_ptr+8];

    cvt.u32.u8 %r_v1, %r_b1;
    cvt.u32.u8 %r_v2, %r_b2;
    setp.ne.u32 %p_diff, %r_v1, %r_v2;
    @%p_diff bra NEXT_PAT;

    add.u32 %r_k, %r_k, 1;
    bra BYTE_LOOP;

MATCH_FOUND:
    atom.global.add.u32 %r_cur_m, [%r_count_base], 1;
    setp.lt.u32 %p_has_slot, %r_cur_m, %r_max_m;
    @!%p_has_slot bra NEXT_PAT;

    ld.global.u32 %r_rule_id, [%r_pat_ptr];
    mul.wide.u32 %r_off64, %r_cur_m, 8;
    add.u64 %r_byte_ptr, %r_match_base, %r_off64;
    st.global.u32 [%r_byte_ptr], %r_rule_id;
    st.global.u32 [%r_byte_ptr+4], %r_pos;

NEXT_PAT:
    add.u32 %r_p, %r_p, 1;
    bra PAT_LOOP;

NEXT_POS:
    add.u32 %r_pos, %r_pos, %r_stride;
    bra POS_LOOP;

SCAN_EXIT:
    ret;
}
)";

struct alignas(128) FlatGPUPattern {
    uint32_t rule_id = 0;
    uint32_t len = 0;
    uint8_t bytes[120] = {0};
};

struct GPUMatchEntry {
    uint32_t rule_id = 0;
    uint32_t offset = 0;
};

} // anonymous namespace

SignatureScanner::SignatureScanner(GPUComputeEngine& engine)
    : engine_(engine) {
    load_default_malware_rules();
    init_gpu_kernels();
}

SignatureScanner::~SignatureScanner() {
    if (cuda_module_ && engine_.supports_custom_kernels()) {
        engine_.unload_kernel_module(cuda_module_);
        cuda_module_ = nullptr;
    }
}

bool SignatureScanner::init_gpu_kernels() {
    if (gpu_kernels_loaded_) return true;
    if (!engine_.supports_custom_kernels()) return false;

    if (!engine_.load_kernel_module(SCANNER_PTX_CODE, &cuda_module_)) {
        std::cerr << "[SignatureScanner] Falló la compilación JIT del módulo PTX en el backend GPU" << std::endl;
        return false;
    }

    if (!engine_.get_kernel_function(cuda_module_, "compute_histogram", &entropy_kernel_fn_) ||
        !engine_.get_kernel_function(cuda_module_, "scan_patterns", &pattern_kernel_fn_)) {
        std::cerr << "[SignatureScanner] Falló la extracción de los kernels PTX del módulo" << std::endl;
        return false;
    }

    gpu_kernels_loaded_ = true;
    return true;
}

void SignatureScanner::add_rule(uint32_t id, const std::string& name, const std::string& category, const std::vector<uint8_t>& pattern) {
    std::lock_guard<std::mutex> lock(rules_mutex_);
    rules_.push_back({id, name, category, pattern});
}

size_t SignatureScanner::rule_count() const {
    std::lock_guard<std::mutex> lock(rules_mutex_);
    return rules_.size();
}

void SignatureScanner::clear_rules() {
    std::lock_guard<std::mutex> lock(rules_mutex_);
    rules_.clear();
}

void SignatureScanner::load_default_malware_rules() {
    std::lock_guard<std::mutex> lock(rules_mutex_);
    rules_.clear();

    auto add_str = [this](uint32_t id, const std::string& name, const std::string& cat, const std::string& str) {
        std::vector<uint8_t> bytes(str.begin(), str.end());
        rules_.push_back({id, name, cat, bytes});
    };

    auto add_hex = [this](uint32_t id, const std::string& name, const std::string& cat, const std::vector<uint8_t>& bytes) {
        rules_.push_back({id, name, cat, bytes});
    };

    // 1. EICAR Standard Antivirus Test Pattern
    add_str(1001, "EICAR-Standard-AV-Test-Signature", "Test_Signature",
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

    // 2. Ransomware Killswitches & Markers
    add_str(1002, "WannaCry-Payload-Marker", "Ransomware_Tripwire", "WANACRY!");
    add_str(1003, "LockBit-Extension-Marker", "Ransomware_Tripwire", ".lockbit");
    add_str(1004, "Ransomware-VSS-Deletion", "Ransomware_Tripwire", "vssadmin delete shadows");
    add_str(1005, "Ransomware-BCDEdit-Disable", "Ransomware_Tripwire", "bcdedit /set {default} recoveryenabled No");

    // 3. Linux Exploits & Shellcodes
    add_hex(1010, "Linux-x86_64-Execve-Shellcode", "Linux_Shellcode",
            {0x48, 0x31, 0xd2, 0x48, 0xbb, 0x2f, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68});
    add_str(1011, "Linux-SUID-Bash-PrivEsc", "Privilege_Escalation", "chmod 4777 /bin/bash");
    add_str(1012, "Linux-Root-Shadow-Tampering", "Privilege_Escalation", "root::0:0:root:/root:/bin/bash");

    // 4. Reverse Shells & C2 Beacons
    add_str(1020, "Linux-Bash-TCP-Reverse-Shell", "Reverse_Shell", "/bin/bash -i >& /dev/tcp/");
    add_str(1021, "Linux-MKFIFO-Netcat-Shell", "Reverse_Shell", "mkfifo /tmp/f; cat /tmp/f | /bin/sh");
    add_str(1022, "Python-PTY-Spawn-Shell", "Reverse_Shell", "pty.spawn(\"/bin/bash\")");

    // 5. Webshells & Backdoors
    add_str(1030, "PHP-Eval-Base64-Webshell", "Webshell", "eval(base64_decode(");
    add_str(1031, "C99-Webshell-Marker", "Webshell", "c99shell");
    add_str(1032, "PHP-System-Passthru-Backdoor", "Webshell", "passthru($_POST[");

    // 6. Binary Packing & Obfuscation
    add_str(1050, "UPX-Packer-Header-Signature", "Packer_Obfuscation", "UPX!");
}

double SignatureScanner::calculate_entropy(const uint8_t* data, size_t size) {
    if (!data || size == 0) return 0.0;

    if (engine_.is_gpu_accelerated() && size >= 4096 && init_gpu_kernels()) {
        try {
            return calculate_entropy_gpu(data, size);
        } catch (...) {
            // Safe resilient fallback to CPU
        }
    }

    return calculate_entropy_cpu(data, size);
}

double SignatureScanner::calculate_entropy_cpu(const uint8_t* data, size_t size) {
    if (!data || size == 0) return 0.0;

    uint32_t counts[256] = {0};
    for (size_t i = 0; i < size; ++i) {
        counts[data[i]]++;
    }

    double entropy = 0.0;
    double total = static_cast<double>(size);
    for (int i = 0; i < 256; ++i) {
        if (counts[i] > 0) {
            double p = static_cast<double>(counts[i]) / total;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

double SignatureScanner::calculate_entropy_gpu(const uint8_t* data, size_t size) {
    ScopedDeviceBuffer buf_data(engine_, size);
    ScopedDeviceBuffer buf_hist(engine_, 256 * sizeof(uint32_t));
    if (!buf_data.valid() || !buf_hist.valid()) return calculate_entropy_cpu(data, size);

    void* d_data = buf_data.get();
    void* d_hist = buf_hist.get();

    std::vector<uint32_t> zero_hist(256, 0);
    engine_.transfer_to_device(d_hist, zero_hist.data(), 256 * sizeof(uint32_t));
    engine_.transfer_to_device(d_data, data, size);

    uint32_t size_u32 = static_cast<uint32_t>(size);
    void* kernel_args[] = { &d_data, &size_u32, &d_hist };

    unsigned int block_size = 256;
    unsigned int grid_size = std::min<unsigned int>((size + block_size - 1) / block_size, 2048);

    bool launched = engine_.launch_kernel(entropy_kernel_fn_,
                                         grid_size, 1, 1,
                                         block_size, 1, 1,
                                         0, nullptr, kernel_args);

    if (!launched) {
        return calculate_entropy_cpu(data, size);
    }

    engine_.synchronize();

    std::vector<uint32_t> host_hist(256, 0);
    engine_.transfer_to_host(host_hist.data(), d_hist, 256 * sizeof(uint32_t));

    double entropy = 0.0;
    double total = static_cast<double>(size);
    for (int i = 0; i < 256; ++i) {
        if (host_hist[i] > 0) {
            double p = static_cast<double>(host_hist[i]) / total;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

BatchScanResult SignatureScanner::scan_buffer(const uint8_t* data, size_t size, int file_id) {
    if (!data || size == 0) {
        BatchScanResult empty;
        empty.backend_used = engine_.get_active_backend_name();
        return empty;
    }

    auto start_time = std::chrono::high_resolution_clock::now();

    // 1. Calculate Shannon Entropy
    double entropy = calculate_entropy(data, size);
    bool is_packed = (entropy >= 7.20); // Standard threshold for encrypted/packed ELF payloads

    BatchScanResult result;

    // 2. Scan for patterns
    if (engine_.is_gpu_accelerated() && size >= 2048 && init_gpu_kernels()) {
        result = scan_gpu_cuda(data, size, file_id);
        if (result.backend_used.empty()) {
            // GPU scan hit a fallback condition
            result = scan_cpu_fallback(data, size, file_id);
        }
    } else {
        result = scan_cpu_fallback(data, size, file_id);
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    double duration_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();

    result.total_bytes_scanned = size;
    result.scan_duration_ms = duration_ms;
    result.entropy_shannon = entropy;
    result.is_suspicious_packed = is_packed;

    if (duration_ms > 0.0) {
        double mb = static_cast<double>(size) / (1024.0 * 1024.0);
        result.throughput_mb_s = mb / (duration_ms / 1000.0);
    }

    return result;
}

BatchScanResult SignatureScanner::scan_gpu_cuda(const uint8_t* data, size_t size, int file_id) {
    (void)file_id;
    BatchScanResult result;

    std::vector<FlatGPUPattern> flat_patterns;
    {
        std::lock_guard<std::mutex> lock(rules_mutex_);
        flat_patterns.reserve(rules_.size());
        for (const auto& r : rules_) {
            if (r.bytes.empty() || r.bytes.size() > 120) continue;
            FlatGPUPattern p;
            p.rule_id = r.id;
            p.len = static_cast<uint32_t>(r.bytes.size());
            std::memcpy(p.bytes, r.bytes.data(), r.bytes.size());
            flat_patterns.push_back(p);
        }
    }

    if (flat_patterns.empty()) {
        result.backend_used = engine_.get_active_backend_name();
        return result;
    }

    // Allocate GPU buffers with RAII (ARCH-01 fix)
    ScopedDeviceBuffer buf_data(engine_, size);
    if (!buf_data.valid()) return result;

    size_t pat_bytes = flat_patterns.size() * sizeof(FlatGPUPattern);
    ScopedDeviceBuffer buf_pats(engine_, pat_bytes);
    if (!buf_pats.valid()) return result;

    uint32_t max_matches = 1024;
    size_t match_bytes = max_matches * sizeof(GPUMatchEntry);
    ScopedDeviceBuffer buf_matches(engine_, match_bytes);
    ScopedDeviceBuffer buf_count(engine_, sizeof(uint32_t));

    if (!buf_matches.valid() || !buf_count.valid()) {
        return result;
    }

    void* d_data = buf_data.get();
    void* d_pats = buf_pats.get();
    void* d_matches = buf_matches.get();
    void* d_count = buf_count.get();

    // Transfer inputs
    uint32_t zero = 0;
    engine_.transfer_to_device(d_count, &zero, sizeof(uint32_t));
    engine_.transfer_to_device(d_data, data, size);
    engine_.transfer_to_device(d_pats, flat_patterns.data(), pat_bytes);

    // Launch pattern search kernel
    uint32_t data_len_u32 = static_cast<uint32_t>(size);
    uint32_t num_pats_u32 = static_cast<uint32_t>(flat_patterns.size());
    void* kernel_args[] = {
        &d_data,
        &data_len_u32,
        &d_pats,
        &num_pats_u32,
        &d_count,
        &d_matches,
        &max_matches
    };

    unsigned int block_size = 256;
    unsigned int grid_size = std::min<unsigned int>((size + block_size - 1) / block_size, 4096);

    bool ok = engine_.launch_kernel(pattern_kernel_fn_,
                                   grid_size, 1, 1,
                                   block_size, 1, 1,
                                   0, nullptr, kernel_args);

    if (!ok) {
        return result; // Triggers CPU fallback (buffers freed automatically by RAII)
    }

    engine_.synchronize();

    uint32_t match_count = 0;
    engine_.transfer_to_host(&match_count, d_count, sizeof(uint32_t));
    if (match_count > max_matches) match_count = max_matches;

    std::vector<GPUMatchEntry> gpu_matches(match_count);
    if (match_count > 0) {
        engine_.transfer_to_host(gpu_matches.data(), d_matches, match_count * sizeof(GPUMatchEntry));
    }

    // Map matches to metadata
    {
        std::lock_guard<std::mutex> lock(rules_mutex_);
        for (const auto& gm : gpu_matches) {
            for (const auto& r : rules_) {
                if (r.id == gm.rule_id) {
                    PatternMatch match;
                    match.rule_id = r.id;
                    match.rule_name = r.name;
                    match.category = r.category;
                    match.offset = gm.offset;
                    result.matches.push_back(match);
                    break;
                }
            }
        }
    }

    result.backend_used = engine_.get_active_backend_name();
    return result;
}

BatchScanResult SignatureScanner::scan_cpu_fallback(const uint8_t* data, size_t size, int file_id) {
    (void)file_id;
    BatchScanResult result;
    result.backend_used = "CPU_AVX2_Fallback";

    std::lock_guard<std::mutex> lock(rules_mutex_);
    for (const auto& r : rules_) {
        if (r.bytes.empty() || r.bytes.size() > size) continue;

        const uint8_t* pat = r.bytes.data();
        size_t pat_len = r.bytes.size();
        size_t max_search = size - pat_len;

        for (size_t i = 0; i <= max_search; ++i) {
            if (data[i] == pat[0]) {
                if (std::memcmp(&data[i], pat, pat_len) == 0) {
                    PatternMatch match;
                    match.rule_id = r.id;
                    match.rule_name = r.name;
                    match.category = r.category;
                    match.offset = i;
                    result.matches.push_back(match);
                }
            }
        }
    }

    return result;
}

} // namespace samulibre::gpu
