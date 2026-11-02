use serde::{Deserialize, Serialize};

/// Reporte de seguridad estructural de un binario ELF en Linux
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfSecurityReport {
    pub is_valid_elf: bool,
    pub is_64bit: bool,
    pub is_pie: bool,
    pub has_wx_segment: bool,
    pub has_executable_stack: bool,
    pub is_upx_packed: bool,
    pub has_header_tampering: bool,
    pub suspicious_strings: Vec<String>,
    pub threat_score: u32,
    pub diagnosis: Option<String>,
}

// Constantes estándar de cabeceras ELF (Linux)
const EI_MAG0: usize = 0;
const EI_MAG1: usize = 1;
const EI_MAG2: usize = 2;
const EI_MAG3: usize = 3;
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;

const _ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1; // Little endian

const _ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

const PT_LOAD: u32 = 1;
const PT_GNU_STACK: u32 = 0x6474e551;

const PF_X: u32 = 1;
const PF_W: u32 = 2;
const _PF_R: u32 = 4;

/// Analiza la estructura interna de un binario ELF (32 y 64 bits) sin dependencias externas
pub fn analyze_elf_security(data: &[u8]) -> Option<ElfSecurityReport> {
    if data.len() < 52 {
        return None;
    }

    // Validar firma mágica ELF (\x7FELF)
    if data[EI_MAG0] != 0x7F || data[EI_MAG1] != b'E' || data[EI_MAG2] != b'L' || data[EI_MAG3] != b'F' {
        return None;
    }

    let is_64bit = data[EI_CLASS] == ELFCLASS64;
    let is_little_endian = data[EI_DATA] == ELFDATA2LSB;

    if !is_little_endian {
        // La gran mayoría de malware Linux en x86/x86_64/ARM es Little Endian
        return None;
    }

    let mut report = ElfSecurityReport {
        is_valid_elf: true,
        is_64bit,
        is_pie: false,
        has_wx_segment: false,
        has_executable_stack: false,
        is_upx_packed: false,
        has_header_tampering: false,
        suspicious_strings: Vec::new(),
        threat_score: 0,
        diagnosis: None,
    };

    // Detección directa de empaquetador UPX (firmas en cabecera o secciones)
    if data.windows(4).any(|w| w == b"UPX!" || w == b"UPX0" || w == b"UPX1" || w == b"UPX2") {
        report.is_upx_packed = true;
        report.threat_score += 40;
    }

    // Análisis de strings maliciosas o de evasión embebidas
    let search_indicators: &[(&[u8], &str)] = &[
        (b"/memfd:", "Ejecución Fileless con memfd"),
        (b"/etc/ld.so.preload", "Secuestro de librerías LD_PRELOAD"),
        (b"/dev/tcp/", "Reverse shell directa mediante /dev/tcp"),
        (b"PTRACE_TRACEME", "Técnica anti-análisis PTrace"),
        (b"init_module", "Inyección de módulo de kernel (LKM Rootkit)"),
        (b"finit_module", "Carga de módulo de kernel dinámico"),
    ];

    for &(sig, desc) in search_indicators {
        if data.windows(sig.len()).any(|w| w == sig) {
            report.suspicious_strings.push(desc.to_string());
            report.threat_score += 25;
        }
    }

    // Parseo de cabeceras según arquitectura
    if is_64bit {
        if data.len() < 64 {
            return Some(report);
        }

        let e_type = u16::from_le_bytes([data[16], data[17]]);
        report.is_pie = e_type == ET_DYN;

        let e_phoff = u64::from_le_bytes([
            data[32], data[33], data[34], data[35],
            data[36], data[37], data[38], data[39],
        ]) as usize;

        let e_phentsize = u16::from_le_bytes([data[54], data[55]]) as usize;
        let e_phnum = u16::from_le_bytes([data[56], data[57]]) as usize;

        let e_shnum = u16::from_le_bytes([data[60], data[61]]) as usize;
        let e_shoff = u64::from_le_bytes([
            data[40], data[41], data[42], data[43],
            data[44], data[45], data[46], data[47],
        ]) as usize;

        // Anomalía: Cabeceras de sección declaradas fuera de rango o eliminadas artificialmente
        if e_shoff != 0 && (e_shoff > data.len() || e_shnum == 0) {
            report.has_header_tampering = true;
            report.threat_score += 30;
        }

        if e_phoff > 0 && e_phentsize >= 56 && e_phnum > 0 {
            for i in 0..e_phnum {
                let offset = e_phoff + (i * e_phentsize);
                if offset + 56 > data.len() {
                    break;
                }
                let p_type = u32::from_le_bytes([
                    data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
                ]);
                let p_flags = u32::from_le_bytes([
                    data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
                ]);

                // W^X Violation: Segmento con permisos de Escritura (PF_W) y Ejecución (PF_X) simultáneos
                if p_type == PT_LOAD && (p_flags & (PF_W | PF_X)) == (PF_W | PF_X) {
                    report.has_wx_segment = true;
                    report.threat_score += 50;
                }

                // Pila ejecutable (PT_GNU_STACK con PF_X)
                if p_type == PT_GNU_STACK && (p_flags & PF_X) != 0 {
                    report.has_executable_stack = true;
                    report.threat_score += 35;
                }
            }
        }
    } else {
        // ELF 32-bit
        let e_type = u16::from_le_bytes([data[16], data[17]]);
        report.is_pie = e_type == ET_DYN;

        let e_phoff = u32::from_le_bytes([data[28], data[29], data[30], data[31]]) as usize;
        let e_phentsize = u16::from_le_bytes([data[42], data[43]]) as usize;
        let e_phnum = u16::from_le_bytes([data[44], data[45]]) as usize;

        if e_phoff > 0 && e_phentsize >= 32 && e_phnum > 0 {
            for i in 0..e_phnum {
                let offset = e_phoff + (i * e_phentsize);
                if offset + 32 > data.len() {
                    break;
                }
                let p_type = u32::from_le_bytes([
                    data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
                ]);
                let p_flags = u32::from_le_bytes([
                    data[offset + 24], data[offset + 25], data[offset + 26], data[offset + 27]
                ]);

                if p_type == PT_LOAD && (p_flags & (PF_W | PF_X)) == (PF_W | PF_X) {
                    report.has_wx_segment = true;
                    report.threat_score += 50;
                }

                if p_type == PT_GNU_STACK && (p_flags & PF_X) != 0 {
                    report.has_executable_stack = true;
                    report.threat_score += 35;
                }
            }
        }
    }

    // Diagnóstico final contextual
    if report.threat_score >= 50 || report.has_wx_segment {
        let mut reasons = Vec::new();
        if report.has_wx_segment {
            reasons.push("Violación W^X (Segmento con Escritura y Ejecución simultánea)");
        }
        if report.is_upx_packed {
            reasons.push("Binario empaquetado con UPX");
        }
        if report.has_executable_stack {
            reasons.push("Pila ejecutable permitida (Riesgo Buffer Overflow)");
        }
        if report.has_header_tampering {
            reasons.push("Cabeceras ELF alteradas");
        }
        if !report.suspicious_strings.is_empty() {
            reasons.push("Cadenas sospechosas de explotación");
        }
        report.diagnosis = Some(format!("Binario ELF sospechoso (Puntaje: {}): {}", report.threat_score, reasons.join(", ")));
    }

    Some(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_minimal_elf64_parsing() {
        // Cabecera ELF64 mínima sintética
        let mut elf = vec![0u8; 128];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // 64-bit
        elf[5] = 1; // Little endian
        elf[16] = 2; // ET_EXEC
        elf[32] = 64; // e_phoff
        elf[54] = 56; // e_phentsize
        elf[56] = 1;  // e_phnum = 1

        // Program Header en offset 64
        // p_type = PT_LOAD (1)
        elf[64] = 1;
        // p_flags = PF_R | PF_W | PF_X (4 | 2 | 1 = 7) -> W^X violation
        elf[68] = 7;

        let report = analyze_elf_security(&elf).expect("Debe ser un ELF válido");
        assert!(report.is_valid_elf);
        assert!(report.is_64bit);
        assert!(report.has_wx_segment, "Debe detectar violación de segmento W^X");
        assert!(report.threat_score >= 50);
    }
}
