#include "elf_feature_extractor.hpp"
#include <elf.h>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <cctype>

namespace samulibre::gpu {

namespace {

// Safe buffer reader to prevent any buffer overrun / out-of-bounds read
template <typename T>
const T* safe_read(const uint8_t* data, size_t size, size_t offset) {
    if (offset + sizeof(T) > size) return nullptr;
    return reinterpret_cast<const T*>(data + offset);
}

} // anonymous namespace

ELFFeatureExtractor::ELFFeatureExtractor(SignatureScanner* scanner)
    : scanner_(scanner) {}

ELFFeatures ELFFeatureExtractor::extract_features(const uint8_t* data, size_t size, const std::string& filename) {
    ELFFeatures feat;
    (void)filename;

    if (!data || size < 4) {
        return feat;
    }

    // 1. Calculate overall file entropy
    if (scanner_) {
        feat.overall_entropy = scanner_->calculate_entropy(data, size);
    } else {
        // Fast local calculation
        uint32_t counts[256] = {0};
        for (size_t i = 0; i < size; ++i) counts[data[i]]++;
        double ent = 0.0;
        double total = static_cast<double>(size);
        for (int i = 0; i < 256; ++i) {
            if (counts[i] > 0) {
                double p = static_cast<double>(counts[i]) / total;
                ent -= p * std::log2(p);
            }
        }
        feat.overall_entropy = ent;
    }

    // 2. Check ELF Magic: 0x7F 'E' 'L' 'F'
    if (data[0] == ELFMAG0 && data[1] == ELFMAG1 && data[2] == ELFMAG2 && data[3] == ELFMAG3) {
        feat.is_valid_elf = true;
        parse_elf_headers(data, size, feat);
        analyze_sections_and_segments(data, size, feat);
    } else {
        // Check for script with shebang: '#!'
        if (data[0] == '#' && data[1] == '!') {
            // Treat as Linux shell / python script
            feat.is_valid_elf = false;
        }
    }

    // 3. Inspect symbols, strings, and suspicious API indicators
    inspect_strings_and_symbols(data, size, feat);

    return feat;
}

void ELFFeatureExtractor::parse_elf_headers(const uint8_t* data, size_t size, ELFFeatures& feat) {
    if (size < EI_NIDENT) return;

    feat.elf_class = data[EI_CLASS]; // 1 = 32-bit, 2 = 64-bit

    if (feat.elf_class == ELFCLASS64) {
        const auto* ehdr = safe_read<Elf64_Ehdr>(data, size, 0);
        if (!ehdr) return;

        feat.machine = ehdr->e_machine;
        feat.entry_point = ehdr->e_entry;
        feat.section_count = ehdr->e_shnum;
        feat.program_header_count = ehdr->e_phnum;
        feat.missing_section_headers = (ehdr->e_shoff == 0 || ehdr->e_shnum == 0);
    } else if (feat.elf_class == ELFCLASS32) {
        const auto* ehdr = safe_read<Elf32_Ehdr>(data, size, 0);
        if (!ehdr) return;

        feat.machine = ehdr->e_machine;
        feat.entry_point = ehdr->e_entry;
        feat.section_count = ehdr->e_shnum;
        feat.program_header_count = ehdr->e_phnum;
        feat.missing_section_headers = (ehdr->e_shoff == 0 || ehdr->e_shnum == 0);
    }
}

void ELFFeatureExtractor::analyze_sections_and_segments(const uint8_t* data, size_t size, ELFFeatures& feat) {
    if (feat.elf_class == ELFCLASS64) {
        const auto* ehdr = safe_read<Elf64_Ehdr>(data, size, 0);
        if (!ehdr) return;

        // A. Analyze Program Headers (Segments)
        bool entry_point_covered = false;
        for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
            size_t ph_offset = ehdr->e_phoff + i * sizeof(Elf64_Phdr);
            const auto* phdr = safe_read<Elf64_Phdr>(data, size, ph_offset);
            if (!phdr) break;

            // Check for W+X (Writable and Executable) segment: highly suspicious
            if ((phdr->p_flags & PF_W) && (phdr->p_flags & PF_X)) {
                feat.has_rwx_section = true;
            }

            // Check if entry point is within executable segments
            if ((phdr->p_flags & PF_X) && (feat.entry_point >= phdr->p_vaddr) &&
                (feat.entry_point < phdr->p_vaddr + phdr->p_memsz)) {
                entry_point_covered = true;
            }
        }

        if (ehdr->e_phnum > 0 && !entry_point_covered && feat.entry_point != 0) {
            feat.entry_point_outside_text = true;
        }

        // B. Analyze Section Headers
        if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0) {
            feat.is_stripped = true;
            return;
        }

        // Find string table section (.shstrtab)
        const char* shstrtab = nullptr;
        size_t shstrtab_size = 0;
        if (ehdr->e_shstrndx < ehdr->e_shnum) {
            size_t str_sh_offset = ehdr->e_shoff + ehdr->e_shstrndx * sizeof(Elf64_Shdr);
            const auto* str_sh = safe_read<Elf64_Shdr>(data, size, str_sh_offset);
            if (str_sh && str_sh->sh_offset + str_sh->sh_size <= size) {
                shstrtab = reinterpret_cast<const char*>(data + str_sh->sh_offset);
                shstrtab_size = str_sh->sh_size;
            }
        }

        for (uint16_t i = 0; i < ehdr->e_shnum; ++i) {
            size_t sh_offset = ehdr->e_shoff + i * sizeof(Elf64_Shdr);
            const auto* shdr = safe_read<Elf64_Shdr>(data, size, sh_offset);
            if (!shdr) break;

            // Check section flags for W+X
            if ((shdr->sh_flags & SHF_WRITE) && (shdr->sh_flags & SHF_EXECINSTR)) {
                feat.has_rwx_section = true;
            }

            // Check section name safely without out-of-bounds reading (VULN-01 fix)
            if (shstrtab && shdr->sh_name < shstrtab_size) {
                size_t max_name_len = shstrtab_size - shdr->sh_name;
                size_t actual_name_len = ::strnlen(shstrtab + shdr->sh_name, max_name_len);
                std::string sname(shstrtab + shdr->sh_name, actual_name_len);
                std::string sname_lower = sname;
                std::transform(sname_lower.begin(), sname_lower.end(), sname_lower.begin(), ::tolower);

                if (sname_lower.find("upx") != std::string::npos ||
                    sname_lower.find("pack") != std::string::npos ||
                    sname_lower.find("cryp") != std::string::npos ||
                    sname_lower.find("stub") != std::string::npos) {
                    feat.has_suspicious_section_name = true;
                }

                // Section entropy for .text
                if (sname == ".text" && shdr->sh_offset + shdr->sh_size <= size && shdr->sh_size > 0) {
                    if (scanner_) {
                        feat.text_section_entropy = scanner_->calculate_entropy(data + shdr->sh_offset, shdr->sh_size);
                    }
                }
                // Section entropy for .data
                if (sname == ".data" && shdr->sh_offset + shdr->sh_size <= size && shdr->sh_size > 0) {
                    if (scanner_) {
                        feat.data_section_entropy = scanner_->calculate_entropy(data + shdr->sh_offset, shdr->sh_size);
                    }
                }
            }
        }
    } else if (feat.elf_class == ELFCLASS32) {
        const auto* ehdr = safe_read<Elf32_Ehdr>(data, size, 0);
        if (!ehdr) return;

        for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
            size_t ph_offset = ehdr->e_phoff + i * sizeof(Elf32_Phdr);
            const auto* phdr = safe_read<Elf32_Phdr>(data, size, ph_offset);
            if (!phdr) break;

            if ((phdr->p_flags & PF_W) && (phdr->p_flags & PF_X)) {
                feat.has_rwx_section = true;
            }
        }
    }
}

void ELFFeatureExtractor::inspect_strings_and_symbols(const uint8_t* data, size_t size, ELFFeatures& feat) {
    if (!data || size == 0) return;

    // Fast search patterns for indicators
    auto has_str = [&](const char* target) -> bool {
        size_t len = std::strlen(target);
        if (len > size) return false;
        const uint8_t* end = data + size - len;
        for (const uint8_t* p = data; p <= end; ++p) {
            if (*p == static_cast<uint8_t>(target[0])) {
                if (std::memcmp(p, target, len) == 0) return true;
            }
        }
        return false;
    };

    // Suspicious API checks
    if (has_str("ptrace") || has_str("TracerPid")) feat.uses_ptrace = true;
    if (has_str("execve") || has_str("system") || has_str("/bin/sh") || has_str("/bin/bash")) feat.uses_execve = true;
    if (has_str("socket") || has_str("connect") || has_str("inet_addr") || has_str("gethostbyname")) feat.uses_sockets = true;
    if (has_str("chmod") || has_str("setuid") || has_str("seteuid") || has_str("cap_set_proc")) feat.manipulates_permissions = true;
    if (has_str("memfd_create")) feat.uses_memfd = true;
    if (has_str("AES_") || has_str("EVP_Encrypt") || has_str("crypto_secretbox")) feat.uses_crypto = true;

    // Suspicious commands / network endpoints
    if (has_str("/dev/tcp/") || has_str("nc -e") || has_str("mkfifo") || has_str("wget") || has_str("curl")) {
        feat.suspicious_strings_count++;
    }
    if (has_str("http://") || has_str("https://")) {
        feat.ip_url_count++;
    }
    if (has_str("eval(base64") || has_str("base64 -d")) {
        feat.base64_strings_count++;
    }
}

MLFeatureVector ELFFeatureExtractor::vectorize(const ELFFeatures& f, size_t file_size) {
    MLFeatureVector vec;
    auto& v = vec.values;

    // Feature 0: Overall file entropy normalized [0.0 - 1.0] (8.0 max)
    v[0] = static_cast<float>(std::clamp(f.overall_entropy / 8.0, 0.0, 1.0));

    // Feature 1: Has RWX section (W+X is strong heuristic indicator for packers/malware)
    v[1] = f.has_rwx_section ? 1.0f : 0.0f;

    // Feature 2: Suspicious section name (UPX, packed, etc.)
    v[2] = f.has_suspicious_section_name ? 1.0f : 0.0f;

    // Feature 3: Entry point anomaly (outside .text section)
    v[3] = f.entry_point_outside_text ? 1.0f : 0.0f;

    // Feature 4: Section count normalized [0 - 40 sections]
    v[4] = static_cast<float>(std::clamp(static_cast<double>(f.section_count) / 40.0, 0.0, 1.0));

    // Feature 5: Is stripped binary
    v[5] = f.is_stripped ? 1.0f : 0.0f;

    // Feature 6: Missing section headers (deliberate evasion)
    v[6] = f.missing_section_headers ? 1.0f : 0.0f;

    // Feature 7: Text section entropy normalized
    v[7] = static_cast<float>(std::clamp(f.text_section_entropy / 8.0, 0.0, 1.0));

    // Feature 8: Data section entropy normalized
    v[8] = static_cast<float>(std::clamp(f.data_section_entropy / 8.0, 0.0, 1.0));

    // Feature 9: Anti-debug indicator (ptrace)
    v[9] = f.uses_ptrace ? 1.0f : 0.0f;

    // Feature 10: Shell execution API (execve, /bin/sh)
    v[10] = f.uses_execve ? 1.0f : 0.0f;

    // Feature 11: Network socket API (connect, socket)
    v[11] = f.uses_sockets ? 1.0f : 0.0f;

    // Feature 12: Crypto / Ransomware indicator
    v[12] = f.uses_crypto ? 1.0f : 0.0f;

    // Feature 13: Privilege escalation API (chmod, setuid)
    v[13] = f.manipulates_permissions ? 1.0f : 0.0f;

    // Feature 14: Fileless execution API (memfd_create)
    v[14] = f.uses_memfd ? 1.0f : 0.0f;

    // Feature 15: Suspicious strings count normalized [0 - 10]
    v[15] = static_cast<float>(std::clamp(static_cast<double>(f.suspicious_strings_count) / 10.0, 0.0, 1.0));

    // Feature 16: Network endpoints (IPs / URLs)
    v[16] = static_cast<float>(std::clamp(static_cast<double>(f.ip_url_count) / 10.0, 0.0, 1.0));

    // Feature 17: Base64 density
    v[17] = static_cast<float>(std::clamp(static_cast<double>(f.base64_strings_count) / 5.0, 0.0, 1.0));

    // Feature 18: File size log normalized: log10(size) / 8.0 (up to 100MB)
    double log_size = file_size > 0 ? std::log10(static_cast<double>(file_size)) : 0.0;
    v[18] = static_cast<float>(std::clamp(log_size / 8.0, 0.0, 1.0));

    // Feature 19: Imported symbols presence
    v[19] = (f.uses_ptrace || f.uses_execve || f.uses_sockets) ? 1.0f : 0.0f;

    // Feature 20: Heuristic high entropy flag (> 7.20 bits)
    v[20] = (f.overall_entropy >= 7.20) ? 1.0f : 0.0f;

    // Feature 21: Packer signature weight
    v[21] = (f.has_suspicious_section_name || (f.has_rwx_section && f.overall_entropy > 7.0)) ? 1.0f : 0.0f;

    // Remaining slots initialized with deterministic baseline characteristics
    for (size_t i = 22; i < MLFeatureVector::DIMENSION; ++i) {
        v[i] = 0.0f;
    }

    return vec;
}

} // namespace samulibre::gpu
