use crate::event_queue::{EdrEventQueue, QueuePriority};
use crate::models::EdrEventType;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct FimRecord {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub mode: u32,
}

pub struct FimSensorHandle {
    stop_signal: Arc<AtomicBool>,
    thread_handle: Option<JoinHandle<()>>,
}

impl Drop for FimSensorHandle {
    fn drop(&mut self) {
        self.stop_signal.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread_handle.take() {
            let _ = h.join();
        }
    }
}

pub struct FimSensor;

impl FimSensor {
    /// Inicia el sensor FIM de monitorización periódica de integridad de rutas críticas
    pub fn start(queue: Arc<EdrEventQueue>) -> FimSensorHandle {
        let stop_signal = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop_signal);

        let thread_handle = std::thread::spawn(move || {
            let critical_paths = get_default_critical_paths();
            let mut baseline: HashMap<PathBuf, FimRecord> = HashMap::new();

            // 1. Establecer línea base inicial
            for p in &critical_paths {
                if let Some(rec) = calculate_fim_record(p) {
                    baseline.insert(p.clone(), rec);
                }
            }

            info!("Sensor FIM activo con {} archivos de sistema en línea base criptográfica.", baseline.len());

            while !stop_clone.load(Ordering::Relaxed) {
                // Ciclo de verificación periódica cada 30 segundos
                std::thread::sleep(std::time::Duration::from_secs(30));

                for p in &critical_paths {
                    if p.exists() {
                        if let Some(current) = calculate_fim_record(p) {
                            if let Some(base) = baseline.get(p) {
                                if base.sha256 != current.sha256 || base.mode != current.mode {
                                    warn!(
                                        "[FIM ALERTA] Violación de integridad en archivo crítico: {:?}",
                                        p
                                    );
                                    queue.enqueue(
                                        QueuePriority::High,
                                        p.clone(),
                                        EdrEventType::FimIntegrityViolation,
                                        None,
                                        None,
                                        None,
                                    );
                                    // Actualizar línea base para evitar alertas en bucle
                                    baseline.insert(p.clone(), current);
                                }
                            } else {
                                // Archivo nuevo detectado en ruta crítica
                                queue.enqueue(
                                    QueuePriority::High,
                                    p.clone(),
                                    EdrEventType::FimIntegrityViolation,
                                    None,
                                    None,
                                    None,
                                );
                                baseline.insert(p.clone(), current);
                            }
                        }
                    } else if baseline.contains_key(p) {
                        warn!("[FIM ALERTA] Archivo crítico eliminado del sistema: {:?}", p);
                        baseline.remove(p);
                    }
                }
            }
        });

        FimSensorHandle {
            stop_signal,
            thread_handle: Some(thread_handle),
        }
    }
}

/// Rutas críticas de seguridad y configuración del sistema Linux
pub fn get_default_critical_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/etc/passwd"),
        PathBuf::from("/etc/shadow"),
        PathBuf::from("/etc/sudoers"),
        PathBuf::from("/etc/sudoers.d"),
        PathBuf::from("/etc/pam.d/common-auth"),
        PathBuf::from("/etc/pam.d/system-auth"),
        PathBuf::from("/etc/systemd/system"),
        PathBuf::from("/etc/crontab"),
        PathBuf::from("/etc/cron.d"),
        PathBuf::from("/etc/ld.so.preload"),
        PathBuf::from("/etc/resolv.conf"),
        PathBuf::from("/etc/hosts"),
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/usr/local/sbin"),
    ]
}

fn calculate_fim_record(path: &Path) -> Option<FimRecord> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() {
        return None;
    }

    let size = metadata.len();
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode()
    };
    #[cfg(not(unix))]
    let mode = 0u32;

    // Calcular hash SHA-256 (hasta 10 MB para no bloquear I/O)
    if size > 10 * 1024 * 1024 {
        return Some(FimRecord {
            path: path.to_path_buf(),
            sha256: "large_file_unhashed".to_string(),
            size,
            mode,
        });
    }

    let bytes = fs::read(path).ok()?;
    let sha256 = hex::encode(Sha256::digest(&bytes));

    Some(FimRecord {
        path: path.to_path_buf(),
        sha256,
        size,
        mode,
    })
}
