use crate::event_queue::{EdrEventQueue, QueuePriority};
use crate::models::EdrEventType;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{error, warn};

#[derive(Debug, Clone)]
struct ProcessWriteWindow {
    writes_count: usize,
    modified_paths: Vec<PathBuf>,
    first_seen: Instant,
    high_entropy_detected: bool,
}

/// Sensor comportamental para detección de ataques de Ransomware y destrucción masiva de ficheros
pub struct BehavioralSensor {
    process_windows: Mutex<HashMap<u32, ProcessWriteWindow>>,
    burst_threshold: usize,
    burst_window_duration: Duration,
}

impl Default for BehavioralSensor {
    fn default() -> Self {
        Self::new(10, Duration::from_secs(2))
    }
}

impl BehavioralSensor {
    pub fn new(burst_threshold: usize, burst_window_duration: Duration) -> Self {
        Self {
            process_windows: Mutex::new(HashMap::new()),
            burst_threshold,
            burst_window_duration,
        }
    }

    /// Registra una operación de escritura o modificación asociada a un proceso
    pub fn record_write_operation(
        &self,
        pid: u32,
        path: &Path,
        queue: &EdrEventQueue,
    ) -> Option<u32> {
        let is_ransomware_extension = is_known_ransomware_extension(path);
        let mut is_high_entropy = false;

        // Comprobar entropía en los primeros 4 KB del archivo
        if let Ok(mut file) = fs::File::open(path) {
            use std::io::Read;
            let mut buf = [0u8; 4096];
            if let Ok(n) = file.read(&mut buf) {
                if n >= 256 {
                    let entropy = calculate_shannon_entropy(&buf[..n]);
                    if entropy > 7.55 {
                        is_high_entropy = true;
                    }
                }
            }
        }

        let mut windows = self.process_windows.lock().ok()?;
        let now = Instant::now();

        let window = windows.entry(pid).or_insert_with(|| ProcessWriteWindow {
            writes_count: 0,
            modified_paths: Vec::new(),
            first_seen: now,
            high_entropy_detected: false,
        });

        // Si expiró la ventana temporal, reiniciar contador
        if now.duration_since(window.first_seen) > self.burst_window_duration {
            window.writes_count = 1;
            window.modified_paths.clear();
            window.modified_paths.push(path.to_path_buf());
            window.first_seen = now;
            window.high_entropy_detected = is_high_entropy;
            return None;
        }

        window.writes_count += 1;
        window.modified_paths.push(path.to_path_buf());
        if is_high_entropy {
            window.high_entropy_detected = true;
        }

        // Evaluar condiciones de alerta de Ransomware
        let is_burst = window.writes_count >= self.burst_threshold;
        let is_suspicious = is_burst && (window.high_entropy_detected || is_ransomware_extension);

        if is_suspicious {
            warn!(
                "[EDR RANSOMWARE] Detectada ráfaga sospechosa de escrituras: PID {} modificó {} archivos con alta entropía o extensión anómala.",
                pid, window.writes_count
            );

            queue.enqueue(
                QueuePriority::Critical,
                path.to_path_buf(),
                EdrEventType::RansomwareBurst,
                Some(pid),
                None,
                None,
            );

            // Retornar el PID infractor para contención inmediata
            return Some(pid);
        }

        None
    }

    /// Suspende inmediatamente el proceso malicioso enviando señal SIGSTOP
    pub fn suspend_process(pid: u32) -> bool {
        #[cfg(unix)]
        {
            unsafe {
                let res = libc::kill(pid as i32, libc::SIGSTOP);
                if res == 0 {
                    warn!("Contención EDR: Proceso PID {} suspendido exitosamente con SIGSTOP.", pid);
                    true
                } else {
                    error!("Fallo al enviar SIGSTOP a PID {}: errno {}", pid, *libc::__errno_location());
                    false
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = pid;
            false
        }
    }
}

/// Extensiones frecuentemente asociadas con cargas útiles de ransomware
fn is_known_ransomware_extension(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
        let lower = ext.to_lowercase();
        matches!(
            lower.as_str(),
            "locked"
                | "crypto"
                | "crypted"
                | "enc"
                | "ransom"
                | "deadbolt"
                | "locky"
                | "cerber"
                | "wnry"
                | "wannacry"
                | "stop"
                | "djvu"
        )
    } else {
        false
    }
}

/// Cálculo de Entropía de Shannon (0.0 a 8.0)
fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len_f = data.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len_f;
            entropy -= p * p.log2();
        }
    }
    entropy
}
