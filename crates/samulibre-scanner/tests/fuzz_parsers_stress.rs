//! Arnés de Fuzzing Automatizado y Pruebas de Estrés para Parsers de SamuLibre
//! Somete los módulos de análisis estático (ELF, Entropía, Hashes Difusos) a miles de mutaciones
//! aleatorias y entradas malformadas para certificar que NUNCA se produzcan pánicos ni accesos fuera de límites.

use samulibre_scanner::elf_analyzer::analyze_elf_security;
use samulibre_scanner::polymorphic::{
    analyze_polymorphic_entropy, calculate_shannon_entropy, compare_fuzzy_hashes, compute_fuzzy_hash,
};

/// Generador pseudoaleatorio de permutaciones deterministas (Xorshift32)
struct SimpleRng {
    state: u32,
}

impl SimpleRng {
    fn new(seed: u32) -> Self {
        Self { state: if seed == 0 { 0x12345678 } else { seed } }
    }

    fn next_u32(&mut self) -> u32 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.state = x;
        x
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(4) {
            let val = self.next_u32().to_le_bytes();
            let len = chunk.len().min(4);
            chunk[..len].copy_from_slice(&val[..len]);
        }
    }
}

#[test]
fn test_fuzz_elf_parser_resilience() {
    let mut rng = SimpleRng::new(0xDEADBEEF);

    // 1. Fuzzing de mutación sobre binario ELF válido de referencia
    let mut base_elf = vec![
        0x7F, b'E', b'L', b'F', // Magic
        2,                       // 64-bit
        1,                       // Little-endian
        1,                       // Version
        0, 0, 0, 0, 0, 0, 0, 0, 0, // Padding
        2, 0,                    // ET_EXEC
        0x3E, 0,                 // x86_64
        1, 0, 0, 0,              // Version 1
        0x78, 0, 0, 0, 0, 0, 0, 0, // Entry point
        0x40, 0, 0, 0, 0, 0, 0, 0, // Phoff
        0, 0, 0, 0, 0, 0, 0, 0,    // Shoff
        0, 0, 0, 0,              // Flags
        64, 0,                   // Ehsize
        56, 0,                   // Phentsize
        1, 0,                    // Phnum
        64, 0,                   // Shentsize
        0, 0,                    // Shnum
        0, 0,                    // Shstrndx
    ];
    // Añadir segmento PT_LOAD
    base_elf.extend_from_slice(&[
        1, 0, 0, 0,              // PT_LOAD
        7, 0, 0, 0,              // PF_R | PF_W | PF_X
        0, 0, 0, 0, 0, 0, 0, 0,  // Offset
        0, 0, 0, 0, 0, 0, 0, 0,  // Vaddr
        0, 0, 0, 0, 0, 0, 0, 0,  // Paddr
        0x10, 0, 0, 0, 0, 0, 0, 0, // Filesz
        0x10, 0, 0, 0, 0, 0, 0, 0, // Memsz
        0, 0x10, 0, 0, 0, 0, 0, 0, // Align
    ]);

    // Ejecutar 2,000 iteraciones de mutación continua
    for _ in 0..2000 {
        let mut mutated = base_elf.clone();
        let num_mutations = (rng.next_u32() % 16) + 1;
        for _ in 0..num_mutations {
            let idx = (rng.next_u32() as usize) % mutated.len();
            mutated[idx] = (rng.next_u32() & 0xFF) as u8;
        }

        // El parser debe retornar Some(_) o None, pero NUNCA provocar pánico
        let _ = analyze_elf_security(&mutated);
    }

    // 2. Fuzzing de tamaños extremos y bordes truncados
    for len in [0, 1, 2, 4, 15, 16, 51, 52, 63, 64, 127, 128, 255, 512, 1024] {
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        let _ = analyze_elf_security(&buf);
    }
}

#[test]
fn test_fuzz_entropy_and_polymorphic_engine() {
    let mut rng = SimpleRng::new(0xCAFEBABE);

    // 1. Fuzzing de cálculo de Entropía de Shannon
    for _ in 0..500 {
        let len = (rng.next_u32() % (64 * 1024)) as usize;
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);

        let entropy = calculate_shannon_entropy(&buf);
        assert!((0.0..=8.0001).contains(&entropy), "Entropía debe estar estrictamente acotada en [0, 8]");
    }

    // 2. Fuzzing de Detección Polimórfica
    for _ in 0..500 {
        let len = (rng.next_u32() % (32 * 1024)) as usize;
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);

        let profile = analyze_polymorphic_entropy(&buf, "fuzz_target.bin");
        assert!(profile.overall_entropy >= 0.0 && profile.overall_entropy <= 8.0001);
    }

    // 3. Fuzzing de Hashes Difusos
    for _ in 0..500 {
        let len = (rng.next_u32() % 8192) as usize;
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);

        let h1 = compute_fuzzy_hash(&buf);
        let h2 = compute_fuzzy_hash(&buf);
        let score = compare_fuzzy_hashes(&h1, &h2);
        if !buf.is_empty() {
            assert!(score >= 90, "Mismo buffer debe tener similitud difusa >= 90%");
        }
    }

    // Fuzzing con cadenas difusas corruptas en compare_fuzzy_hashes
    assert_eq!(compare_fuzzy_hashes("", ""), 0);
    assert_eq!(compare_fuzzy_hashes("invalid:hash", "malformed"), 0);
    assert_eq!(compare_fuzzy_hashes("10:abc:def:extra", "10:abc:def"), 0);
}
